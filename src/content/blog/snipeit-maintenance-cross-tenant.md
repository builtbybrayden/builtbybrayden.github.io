---
title: 'How a Missing Company Check Let Any Snipe-IT User Move Maintenance Records Between Companies'
description: 'A mass-assignment bug in the Snipe-IT Maintenances API let a user in one company re-parent maintenance records onto assets in another. CVE-2026-55516, CVSS 7.7.'
pubDate: '2026-07-25'
---

## Background

Snipe-IT supports a multi-tenant mode called Full Multiple Companies Support (FMCS), aimed at organizations that run several separate business units, subsidiaries, or clients out of a single Snipe-IT instance. The entire point of FMCS is that a user scoped to Company A cannot see or touch Company B's data. Snipe-IT enforces that boundary consistently on reads. This finding is about a place where it didn't enforce it on writes.

## The vulnerability class

This is a mass-assignment bug (CWE-915) that turns into an authorization bypass through a user-controlled key (CWE-639) and, more broadly, improper authorization (CWE-285). The pattern shows up constantly in web apps: a controller checks whether the caller can perform an action in general, but never checks whether the specific object the caller is targeting is one they're allowed to touch.

## Root cause

I first confirmed FMCS was actually being enforced elsewhere, as a control. Requesting an asset that belongs to a different company through the read API returns a clean rejection:

```bash
curl -H "Authorization: Bearer $TOKEN" http://.../api/v1/hardware/2
# {"status":"error","messages":"Asset does not exist."}
```

So the platform does the right thing on reads. The Maintenances controller didn't match that on writes.

`MaintenancesController::store()` authorized only at the class level, `$this->authorize('update', Asset::class)`, and never checked whether the caller-supplied `asset_id` belonged to a company they had access to:

```php
public function store(ImageUploadRequest $request): JsonResponse|array
{
    $this->authorize('update', Asset::class);      // class-level, no asset_id check
    $maintenance = new AssetMaintenance;
    $maintenance->fill($request->all());            // writes attacker's asset_id straight through
    $maintenance->user_id = Auth::id();
    // ...
}
```

`update()` was subtler. It checked tenancy on the maintenance record's *current* asset before the fill, which looks correct at a glance, but then filled the request body (which can include a new `asset_id`) and saved without ever re-checking the *new* target:

```php
public function update(Request $request, $id): JsonResponse|array
{
    $this->authorize('update', Asset::class);
    $maintenance = AssetMaintenance::with('asset')->findOrFail($id);

    if (! Company::isCurrentUserHasAccess($maintenance->asset)) {   // checks the OLD asset
        return response()->json(...403...);
    }

    $maintenance->fill($request->all());    // can silently change asset_id to anything
    // no re-check on the new asset_id
}
```

Pre-fill checks on post-fill data are a recurring failure shape. The check runs against state that's about to be replaced.

## Proof of concept

Working in an isolated Docker lab with two companies seeded (Company A with one asset, Company B with two), I created a user scoped to Company A with ordinary asset permissions (view, edit, create) and no superuser flag.

**Store path.** A single POST with a Company B asset ID succeeded outright:

```bash
curl -X POST .../api/v1/maintenances \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"cross-tenant-test","asset_id":2,"asset_maintenance_type":"Repair", ...}'
# 200 success
```

The resulting database row showed exactly the mismatch FMCS is supposed to prevent: the maintenance record's creator belonged to Company A, but the asset it referenced belonged to Company B.

**Update path.** I had the test user legitimately create a maintenance record on her own company's asset, then PATCH that same record's `asset_id` to point at a Company B asset:

```bash
curl -X PUT .../api/v1/maintenances/2 -H "Authorization: Bearer $TOKEN" -d '{"asset_id":2}'
# 200 success
```

Same result: a maintenance record now attached to an asset in a company the test user has no read access to whatsoever.

## Impact

A user in one company can attribute maintenance history, cost data, and repair events to assets belonging to a company they can't even see through the normal UI. For an organization using Snipe-IT as the system of record for asset lifecycle and chargeback reporting, that's a quiet integrity problem: reports that aggregate by company can be polluted by users who were never supposed to have any visibility into that company's inventory. The bug is silent. Neither company gets an error or a warning.

The update-path variant carries a CVSS 3.1 score of 7.7 (High), vector `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N`, per Grokability's published scoring.

## Timeline

Reported to `security@snipeitapp.com` on May 2, 2026. Grokability fixed the store path within about two days, in commit [`0daec32ddd52`](https://github.com/grokability/snipe-it/commit/0daec32ddd52ca355ea48c73996befb592733e54), by introducing a dedicated maintenance permission and policy. The update path took a bit longer, landing about six weeks later in commit [`905d498ecdb0`](https://github.com/grokability/snipe-it/commit/905d498ecdb0ee5591231c97bf48435e92044368), shipped in v8.6.2. Both paths are confirmed fixed.

The update-path variant is now public as [GHSA-575r-357h-fhch](https://github.com/grokability/snipe-it/security/advisories/GHSA-575r-357h-fhch) / **CVE-2026-55516**. Another researcher, 5h1kh4r, independently found and reported the same update-path bug, and Grokability credited both of us as reporters on the published advisory. The store-path variant doesn't have a separate public CVE at this time.

## The fix

The update-path fix does exactly what was missing: it re-resolves and re-authorizes against the *new* asset ID before saving, instead of trusting the pre-fill check.

```php
if ($request->filled('asset_id') && (int) $request->input('asset_id') !== $maintenance->asset_id) {
    $newAsset = Asset::find($request->input('asset_id'));
    if (! $newAsset) {
        return response()->json(Helper::formatStandardApiResponse('error', null, trans('general.not_found')), 404);
    }
    if (! Company::isCurrentUserHasAccess($newAsset)) {
        return response()->json(Helper::formatStandardApiResponse('error', null, trans('general.insufficient_permissions')), 403);
    }
    $maintenance->fill($request->except('asset_id'));
    $maintenance->asset_id = $newAsset->id;
} else {
    $maintenance->fill($request->except('asset_id'));
}
```

## Takeaway

When a write path accepts a foreign key from the request body, the authorization check has to run against the value that key resolves to *after* the request is applied, not before. A tenancy check performed on stale, pre-fill state gives you the comforting appearance of a guard rail without the guard rail actually being there for the field that matters.

---

*Reported by Brayden Arnold ([@builtbybrayden](https://github.com/builtbybrayden)). Snipe-IT is open source at [github.com/grokability/snipe-it](https://github.com/grokability/snipe-it).*
