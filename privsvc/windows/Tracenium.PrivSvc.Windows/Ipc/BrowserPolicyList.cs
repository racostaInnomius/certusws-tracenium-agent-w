// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/BrowserPolicyList.cs
//
// `browser.policy_list.read`  { browser, list }                    → { entries }
// `browser.policy_list.write` { browser, list, expected, entries }  → { status, entries }
//
// status: written | unchanged | conflict. Ver BrowserPolicyListShape.cs para
// qué se acepta y por qué el primitivo es tan estrecho.

using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class BrowserPolicyList
{
    private static List<string> ReadEntries(RegistryKey hklm, string subKey)
    {
        using var key = hklm.OpenSubKey(subKey, writable: false);
        if (key is null) return new List<string>();
        return BrowserPolicyListShape.OrderedEntries(
            key.GetValueNames().Select(n => (n, key.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames))));
    }

    public static Task<PrivSvcResponse> HandleRead(PrivSvcRequest req)
    {
        var browser = BrowserPolicyListShape.StringParam(req.Params, "browser");
        var list = BrowserPolicyListShape.StringParam(req.Params, "list");
        var subKey = BrowserPolicyListShape.KeyFor(browser, list);
        if (subKey is null) return Task.FromResult(PrivSvcResponse.Fail(req.Id, "INVALID_PARAMS", "browser must be chrome|edge and list blocklist|allowlist"));
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { browser, list, entries = ReadEntries(hklm, subKey) }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "REGISTRY_READ_FAILED", ex.GetType().Name));
        }
    }

    public static Task<PrivSvcResponse> HandleWrite(PrivSvcRequest req)
    {
        var browser = BrowserPolicyListShape.StringParam(req.Params, "browser");
        var list = BrowserPolicyListShape.StringParam(req.Params, "list");
        var subKey = BrowserPolicyListShape.KeyFor(browser, list);
        var expected = BrowserPolicyListShape.ListParam(req.Params, "expected");
        var entries = BrowserPolicyListShape.ListParam(req.Params, "entries");
        if (subKey is null || expected is null || entries is null)
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "INVALID_PARAMS", "browser, list, expected[] and entries[] are required"));

        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var current = ReadEntries(hklm, subKey);
            if (!current.SequenceEqual(expected, StringComparer.Ordinal))
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new { browser, list, status = "conflict", entries = current }));
            if (current.SequenceEqual(entries, StringComparer.Ordinal))
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new { browser, list, status = "unchanged", entries = current }));

            var reject = BrowserPolicyListShape.RejectReason(list!, entries, current);
            if (reject is not null) return Task.FromResult(PrivSvcResponse.Fail(req.Id, "INVALID_ENTRIES", reject));

            using (var key = hklm.CreateSubKey(subKey, writable: true))
            {
                for (var i = 0; i < entries.Count; i++)
                    key.SetValue((i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), entries[i], RegistryValueKind.String);
                foreach (var name in BrowserPolicyListShape.NamesToDelete(key.GetValueNames(), entries.Count))
                    key.DeleteValue(name, throwOnMissingValue: false);
            }
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { browser, list, status = "written", entries = ReadEntries(hklm, subKey) }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "REGISTRY_WRITE_FAILED", ex.GetType().Name));
        }
    }
}
