---
title: 'CVE-2026-86765: How Editing an Asset Could Quietly Check It Out Too'
description: 'A missing authorization check in Snipe-IT let a user with only asset-edit rights push assignment fields through the update endpoint and check out equipment they were explicitly denied checkout access to. Rated Medium severity, CVSS 6.5.'
pubDate: '2026-09-19'
---

## The short version

Snipe-IT lets an administrator split permissions finely: a role can be allowed to edit an asset's records (serial number, notes, custom fields) while being explicitly *denied* the separate permission to check equipment in or out. That split is meant to be a real boundary, useful for organizations where updating inventory data and actually handing out physical equipment are two different jobs with two different levels of trust.

The boundary had a gap. The asset **update** endpoint accepted the same assignment fields the dedicated checkout endpoint uses, but never asked whether the caller actually had checkout permission, and never checked whether the asset was even in a state that's allowed to be checked out. A user who could only edit assets could use the update endpoint to check out unassigned equipment, assign equipment sitting in a non-deployable status, or transfer already-deployed equipment straight to a new custodian without an intervening check-in.

This is tracked as **CVE-2026-86765** (CVSS 6.5, Medium), fixed in Snipe-IT 8.7.0.

## Some background

Snipe-IT's permission model is granular by design. `assets.edit` and `assets.checkout` are separate permissions, and plenty of real deployments rely on that separation: front-line IT staff might be trusted to keep asset records accurate (serials, locations, notes) without being trusted to actually walk equipment out the door. Checkout is treated as the more sensitive action, since it changes who is physically accountable for a piece of equipment.

There are two ways to check something out in the app: a dedicated checkout endpoint, and the general-purpose asset update endpoint (`PATCH /api/v1/hardware/{asset_id}`), which also accepts `assigned_user`, `assigned_asset`, and `assigned_location` fields for backwards compatibility with older API callers. The dedicated endpoint correctly gates on the checkout permission. The update endpoint didn't.

## What went wrong

The update endpoint's logic ran roughly like this: if the request included any of the assignment fields, treat it as a checkout request, resolve the target (user, asset, or location), and confirm the target belongs to the same company as the caller. That company check passed, and the record was saved with the new assignment, no matter what the caller's checkout permission actually said.

Two things were missing:

**No checkout-permission check.** The dedicated checkout endpoint gates on `Gate::allows('checkout', $asset)`. The update path never asked this question at all, so `assets.edit` was effectively enough to perform a checkout, even for a role with checkout explicitly denied.

**No availability check.** The dedicated checkout endpoint also confirms the asset is actually eligible to be checked out: not already assigned to someone, and in a deployable status. The update path skipped this too, which meant it could silently reassign an asset that was already checked out to someone else (recorded as a second checkout event with no check-in in between), or check out an asset sitting in a Pending or otherwise non-deployable status.

In CWE terms: missing authorization (CWE-862) on the permission itself, combined with improper enforcement of the intended checkout/check-in workflow (CWE-841). The update path reused business logic (`$asset->checkOut()`) that assumed it was only ever reachable through the properly-gated checkout endpoint, and the assumption didn't hold.

Here's the relevant shape of the pre-fix code:

```php
$target = $this->resolveCheckoutTargetForAssetMutation($request, $asset->id);
$requestedCheckout = $request->filled('assigned_user')
    || $request->filled('assigned_asset')
    || $request->filled('assigned_location');

if ($requestedCheckout && ! $target) {
    // ...target not found
}

if ($requestedCheckout && ! $asset->canCheckoutTo($target)) {
    // ...target belongs to a different company
}

// No check of Gate::allows('checkout', $asset)
// No check of $asset->availableForCheckout()

$updated = DB::transaction(function () use ($asset, $request, $target, $requestedCheckout): bool {
    if (! $asset->save()) {
        return false;
    }

    if ($requestedCheckout) {
        // ...proceeds straight to $asset->checkOut(...)
    }
    // ...
});
```

`canCheckoutTo()` only confirms the target is in the right company. It says nothing about whether the *caller* is allowed to check anything out, or whether the *asset* is in a checkout-eligible state.

## Why this matters

If your organization relies on Snipe-IT's permission split to keep "who can edit inventory records" and "who can hand out physical equipment" as genuinely different levels of trust, this bug meant that split wasn't being enforced everywhere. A user who was deliberately scoped down to edit-only access could still move equipment around: assign unassigned gear to themselves or someone else, pull a device out of Pending status before it was actually ready to deploy, or re-point an already-deployed asset to a new custodian without the check-in step that's supposed to record the handoff. None of that requires any special access beyond ordinary asset-edit rights, and none of it goes through the audit path the dedicated checkout endpoint provides.

## Timeline

I reported this to Snipe-IT's maintainer, Grokability, on May 2, 2026, the same report that covered the maintenance cross-tenant issue I wrote about separately ([CVE-2026-55516](/blog/snipeit-maintenance-cross-tenant)). Another researcher, nullbenny, is also credited as a reporter on this advisory. The fix shipped in version 8.7.0, and the advisory was published on August 24, 2026, as [GHSA-6g2g-83pc-6365](https://github.com/grokability/snipe-it/security/advisories/GHSA-6g2g-83pc-6365).

## The fix

The patch adds both of the missing checks before the update is allowed to proceed as a checkout:

```php
if ($requestedCheckout && ! Gate::allows('checkout', $asset)) {
    return [
        'success' => false,
        'asset' => null,
        'message' => null,
        'errors' => null,
        'encrypted_field_warning' => false,
        'error_response_key' => 'general.unauthorized',
    ];
}

if ($requestedCheckout && ! $asset->availableForCheckout()) {
    return [
        'success' => false,
        'asset' => null,
        'message' => null,
        'errors' => null,
        'encrypted_field_warning' => false,
        'error_response_key' => 'admin/hardware/message.checkout.not_available',
    ];
}
```

Now the update endpoint enforces the same two rules the dedicated checkout endpoint always has: the caller needs checkout permission, and the asset needs to actually be in a state where checkout makes sense.

## Takeaway

A permission split is only as strong as its weakest entry point. Snipe-IT had the right permission model, `assets.edit` and `assets.checkout` as genuinely separate grants, and the right gate on the endpoint built for checkout. But a second, more general endpoint reused the same underlying state change (`$asset->checkOut()`) without reusing the same gate. Whenever an action can be triggered through more than one route, every route needs its own copy of the authorization check; a check that lives only on the "obvious" endpoint isn't a check on the action, it's a check on that one door.

---

*Reported by Brayden Arnold ([@builtbybrayden](https://github.com/builtbybrayden)), alongside nullbenny. Snipe-IT is open source at [github.com/grokability/snipe-it](https://github.com/grokability/snipe-it).*
