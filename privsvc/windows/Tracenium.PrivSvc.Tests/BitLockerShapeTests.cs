// privsvc/windows/Tracenium.PrivSvc.Tests/BitLockerShapeTests.cs
//
// BitLocker por volumen, con los estados como texto. Lo que se fija: el
// volumen de sistema cifrado con la protección SUSPENDIDA no pasa por
// cifrado; un estado numérico no se interpreta; sin lectura es unknown.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class BitLockerShapeTests
{
    private static Dictionary<string, object?> System(Dictionary<string, object?> b) =>
        Assert.IsType<Dictionary<string, object?>>(b["systemVolume"]);

    [Fact]
    public void System_volume_encrypted_and_protected()
    {
        var b = BitLockerShape.Parse("[{\"MountPoint\":\"C:\",\"VolumeType\":\"OperatingSystem\",\"VolumeStatus\":\"FullyEncrypted\",\"ProtectionStatus\":\"On\",\"EncryptionPercentage\":100},{\"MountPoint\":\"D:\",\"VolumeType\":\"Data\",\"VolumeStatus\":\"FullyDecrypted\",\"ProtectionStatus\":\"Off\",\"EncryptionPercentage\":0}]");
        var s = System(b);
        Assert.Equal("C:", s["mountPoint"]);
        Assert.Equal(true, s["encrypted"]);
        Assert.Equal(true, s["protectionOn"]);
        Assert.Equal("enabled", b["status"]);
        Assert.Equal(new List<string> { "C:" }, b["drives"]);
        Assert.Equal(0.5, b["coverage"]);
    }

    [Fact]
    public void Suspended_protection_is_encrypted_but_not_protected()
    {
        var s = System(BitLockerShape.Parse("{\"MountPoint\":\"C:\",\"VolumeType\":\"OperatingSystem\",\"VolumeStatus\":\"FullyEncrypted\",\"ProtectionStatus\":\"Off\",\"EncryptionPercentage\":100}"));
        Assert.Equal(true, s["encrypted"]);
        Assert.Equal(false, s["protectionOn"]);
    }

    [Fact]
    public void Only_a_data_volume_encrypted_does_not_make_the_system_volume_encrypted()
    {
        var b = BitLockerShape.Parse("[{\"MountPoint\":\"C:\",\"VolumeType\":\"OperatingSystem\",\"VolumeStatus\":\"FullyDecrypted\",\"ProtectionStatus\":\"Off\"},{\"MountPoint\":\"E:\",\"VolumeType\":\"Data\",\"VolumeStatus\":\"FullyEncrypted\",\"ProtectionStatus\":\"On\"}]");
        Assert.Equal("enabled", b["status"]); // el campo antiguo seguía diciendo esto
        Assert.Equal(false, System(b)["encrypted"]);
    }

    [Fact]
    public void Numeric_enum_values_are_not_guessed()
    {
        // Lo que emitía el script antiguo en Windows PowerShell 5.1.
        var b = BitLockerShape.Parse("{\"MountPoint\":\"C:\",\"VolumeType\":0,\"VolumeStatus\":1,\"ProtectionStatus\":1}");
        Assert.False(b.ContainsKey("systemVolume"));
        Assert.Equal("disabled", b["status"]);
    }

    [Fact]
    public void Encryption_in_progress_is_not_encrypted()
    {
        var s = System(BitLockerShape.Parse("{\"MountPoint\":\"C:\",\"VolumeType\":\"OperatingSystem\",\"VolumeStatus\":\"EncryptionInProgress\",\"ProtectionStatus\":\"Off\",\"EncryptionPercentage\":42}"));
        Assert.Equal(false, s["encrypted"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("oops")]
    [InlineData("[]")]
    public void No_readable_output_is_unknown(string? json)
    {
        var b = BitLockerShape.Parse(json);
        Assert.Equal("unknown", b["status"]);
        Assert.False(b.ContainsKey("systemVolume"));
    }
}
