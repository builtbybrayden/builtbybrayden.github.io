---
title: 'CVE-2026-55516: How a Missing Check Let Snipe-IT Users Reach Into Another Company''s Data'
description: 'A missing permission check in Snipe-IT let one company silently attach maintenance records to another company''s equipment. Rated High severity, CVSS 7.7.'
pubDate: '2026-07-25'
---

## The short version

Snipe-IT is an open source tool a lot of IT teams use to track laptops, software licenses, and other equipment. It has a mode built for organizations that manage several separate companies out of one account, each company's data walled off from the others. I found a bug where that wall had a gap: a user in one company could attach maintenance records to equipment belonging to a company they weren't supposed to see at all. No error, no warning, nothing in the interface hinted it had happened.

It's fixed now. The bug is tracked as **CVE-2026-55516**, rated High severity (CVSS 7.7).

## Some background

If you're not familiar with Snipe-IT: it's the kind of software an IT department uses to answer "who has laptop #4471, when did it last get serviced, and is the warranty still good." A lot of organizations that manage IT for multiple companies at once, think a managed service provider, or a parent company with several subsidiaries, use a feature called Full Multiple Companies Support (FMCS). The idea is simple: one Snipe-IT account, several companies inside it, and a hard rule that a user tied to Company A should never be able to see or touch Company B's equipment.

Snipe-IT gets this right almost everywhere. If a Company A user asks the system to show them an asset that belongs to Company B, they get told it doesn't exist, a clean, correct rejection. I went looking for a place where that rule wasn't actually being enforced, and found one in the part of the app that handles maintenance records (the repair history, service dates, and costs tied to a piece of equipment).

## What went wrong

Picture two companies sharing the same Snipe-IT account, each with their own set of laptops and other gear. The system is supposed to work like two locked filing cabinets in the same room: Company A has a key to their cabinet, Company B has a key to theirs, and neither can open the other's drawer.

The maintenance-records feature had two ways to create or update a record, and both of them let a user write into the wrong cabinet if they simply mentioned the right asset ID.

**Creating a new maintenance record.** The endpoint checked whether you were generally allowed to create maintenance records at all, but never checked whether the specific piece of equipment you named actually belonged to your company. So a Company A user could submit "create a maintenance record for asset #2" even when asset #2 belonged to Company B, and the system would go ahead and create it.

**Updating an existing record.** This one was sneakier. When you asked to update a maintenance record, the system correctly checked whether you had rights to the equipment the record was *currently* attached to. That check passes, because you do own that record. But the same request could also include a change of which asset the record points to, and the system never re-checked that new target. So you could take a maintenance record you legitimately own, and quietly re-point it at a piece of equipment belonging to a different company, and the second check that should have caught this simply never ran.

If you want the technical framing: this is a mass-assignment bug (CWE-915, a class of vulnerability where user-supplied fields get written to the database without the right checks) that turns into a full authorization bypass through a user-controlled key (CWE-639) and, more broadly, improper authorization (CWE-285). The field being trusted, the target asset ID, was exactly the thing that should have determined whether the action was allowed at all.

Here's the code for the update path, which is the more interesting of the two. It checks access to the *old* asset, then quietly lets the request swap in a new one:

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

The lesson generalizes past this one bug: when a request can change which record it points to, checking permissions on the *old* target and then trusting the *new* one is a gap, and it's an easy one to introduce by accident because the code reads as correct at a glance.

## How I found it and proved it

I do this kind of research in an isolated lab, never against a live company's data. I set up a local copy of Snipe-IT with two fake companies: Company A with one piece of equipment, Company B with two. I created a test user belonging to Company A with completely ordinary permissions, no admin rights, nothing special.

From there, two tests:

**Test one.** As the Company A user, I sent a request to create a new maintenance record and pointed it at one of Company B's assets. It worked. The record was created, owned by a Company A user, attached to Company B equipment.

**Test two.** I had the same user create a legitimate maintenance record on their own company's equipment first, then sent a follow-up request changing which asset it pointed to, aiming it at a Company B asset instead. That also worked, silently re-parenting a record the user had no business touching.

Neither test produced an error message, a warning, or anything a normal user or an administrator watching the system would notice.

## Why this matters

If your organization uses Snipe-IT to keep an accurate, trustworthy record of equipment maintenance, warranty status, and repair costs (which is the whole point of the tool), this bug meant that record could be quietly polluted by people who weren't supposed to have any visibility into your company at all. A managed service provider running several client companies through one account is exactly the deployment shape where this bites hardest: one client's maintenance history could get contaminated by another client's activity, with no way to tell it happened until someone went looking.

## Timeline

I reported this to Snipe-IT's maintainer, Grokability, on May 2, 2026. They fixed the "create" path within about two days. The trickier "update" path took longer to land, about six weeks, and shipped in version 8.6.2. Both are confirmed fixed as of this writing.

The update-path fix is documented publicly as [GHSA-575r-357h-fhch](https://github.com/grokability/snipe-it/security/advisories/GHSA-575r-357h-fhch), assigned **CVE-2026-55516**. Another researcher, 5h1kh4r, independently found and reported the same bug around the same time, and Grokability credited both of us as reporters on the published advisory, which is exactly the right way to handle that kind of overlap.

## The fix

The fix does the thing that was missing: before saving the update, it re-checks whether the user actually has access to the *new* asset, not just the old one.

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

If your application lets a request change which record something points to, whether that's a company, a user, or an asset like here, the permission check needs to run against where the request is trying to go, not where it started. A check performed against the old, about-to-be-replaced state gives you the appearance of a guard rail without the guard rail actually doing its job on the field that matters most.

---

*Reported by Brayden Arnold ([@builtbybrayden](https://github.com/builtbybrayden)). Snipe-IT is open source at [github.com/grokability/snipe-it](https://github.com/grokability/snipe-it).*
