// privsvc/windows/Tracenium.PrivSvc.Tests/PlatformIntegrityShapeTests.cs
//
// TPM y Secure Boot: una lectura fallida es "unknown", nunca "ausente" o
// "apagado". Las salidas son las del script de PlatformIntegrityShape.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class PlatformIntegrityShapeTests
{
    [Fact]
    public void Tpm_present_and_ready_from_Get_Tpm()
    {
        var b = PlatformIntegrityShape.ParseTpm("{\"GetTpmOk\":true,\"Present\":true,\"Ready\":true,\"Enabled\":true,\"Activated\":true,\"WmiOk\":true,\"WmiFound\":true,\"SpecVersion\":\"2.0, 0, 1.38\",\"WmiEnabled\":true,\"WmiActivated\":true}");
        Assert.Equal(true, b["present"]);
        Assert.Equal(true, b["ready"]);
        Assert.Equal("2.0", b["version"]);
        Assert.False(b.ContainsKey("status"));
    }

    [Fact]
    public void Get_Tpm_failing_but_WMI_seeing_a_TPM_is_present_not_absent()
    {
        // Lo que mandaban las QEMU de T1: present:false con version 2.0.
        var b = PlatformIntegrityShape.ParseTpm("{\"GetTpmOk\":false,\"Present\":null,\"Ready\":null,\"Enabled\":null,\"Activated\":null,\"WmiOk\":true,\"WmiFound\":true,\"SpecVersion\":\"2.0, 0, 1.59\",\"WmiEnabled\":true,\"WmiActivated\":true}");
        Assert.Equal(true, b["present"]);
        Assert.Equal(true, b["ready"]);
        Assert.Equal("2.0", b["version"]);
    }

    [Fact]
    public void WMI_only_without_enabled_or_activated_does_not_invent_ready()
    {
        var b = PlatformIntegrityShape.ParseTpm("{\"GetTpmOk\":false,\"WmiOk\":true,\"WmiFound\":true,\"SpecVersion\":\"2.0\",\"WmiEnabled\":null,\"WmiActivated\":null}");
        Assert.Equal(true, b["present"]);
        Assert.False(b.ContainsKey("ready"));
        Assert.Equal("partial", b["status"]);
    }

    [Theory]
    [InlineData("{\"GetTpmOk\":true,\"Present\":false,\"Ready\":false,\"WmiOk\":true,\"WmiFound\":false,\"SpecVersion\":null}")]
    [InlineData("{\"GetTpmOk\":false,\"WmiOk\":true,\"WmiFound\":false,\"SpecVersion\":null}")]
    public void Absence_stated_by_a_source_that_answered_is_a_finding(string json)
    {
        var b = PlatformIntegrityShape.ParseTpm(json);
        Assert.Equal(false, b["present"]);
        Assert.Equal(false, b["ready"]);
        Assert.Equal("", b["version"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{\"GetTpmOk\":false,\"WmiOk\":false,\"WmiFound\":false}")]
    public void Tpm_read_failure_is_unknown_without_evaluated_fields(string? json)
    {
        var b = PlatformIntegrityShape.ParseTpm(json);
        Assert.Equal("unknown", b["status"]);
        Assert.False(b.ContainsKey("present"));
        Assert.False(b.ContainsKey("ready"));
        Assert.False(b.ContainsKey("version"));
    }

    [Theory]
    [InlineData("{\"Enabled\":true,\"Unsupported\":false,\"Failed\":false}", true)]
    [InlineData("{\"Enabled\":false,\"Unsupported\":false,\"Failed\":false}", false)]
    public void SecureBoot_read_ok_reports_the_real_value(string json, bool expected)
    {
        var b = PlatformIntegrityShape.ParseSecureBoot(json);
        Assert.Equal(expected, b["enabled"]);
    }

    [Fact]
    public void Legacy_BIOS_is_secure_boot_off()
    {
        var b = PlatformIntegrityShape.ParseSecureBoot("{\"Enabled\":null,\"Unsupported\":true,\"Failed\":false}");
        Assert.Equal(false, b["enabled"]);
        Assert.Equal(true, b["legacyBoot"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("{\"Enabled\":null,\"Unsupported\":false,\"Failed\":true}")]
    [InlineData("{\"Enabled\":null,\"Unsupported\":false,\"Failed\":false}")]
    public void SecureBoot_read_failure_is_unknown(string? json)
    {
        var b = PlatformIntegrityShape.ParseSecureBoot(json);
        Assert.Equal("unknown", b["status"]);
        Assert.False(b.ContainsKey("enabled"));
    }
}
