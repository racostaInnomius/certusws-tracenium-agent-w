// privsvc/windows/Tracenium.PrivSvc.Tests/AuditpolShapeTests.cs
//
// Fase 1 del cierre de brecha CIS. El CSV de `auditpol /backup` se indexa
// por GUID y el ajuste sale del número, nunca del texto localizado.

using Tracenium.PrivSvc.Windows.Ipc;
using Xunit;

public class AuditpolShapeTests
{
    private const string Csv =
        "﻿Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n" +
        "PC1,System,Validación de credenciales,{0CCE923F-69AE-11D9-BED3-505054503030},Éxito y error,,3\r\n" +
        "PC1,System,Administración de cuentas de usuario,{0CCE9235-69AE-11D9-BED3-505054503030},Correcto,,1\r\n" +
        "PC1,System,Actividad PNP,{0CCE9248-69AE-11D9-BED3-505054503030},Sin auditoría,,0\r\n" +
        "PC1,System,\"Grupo, con coma\",{0CCE9237-69AE-11D9-BED3-505054503030},Error,,2\r\n";

    [Fact]
    public void IndexesByLowercaseGuidWithCanonicalEnglishSetting()
    {
        var ev = AuditpolShape.ParseBackupCsv(Csv)!;
        var byGuid = (Dictionary<string, string>)ev["byGuid"]!;
        Assert.Equal("Success and Failure", byGuid["0cce923f-69ae-11d9-bed3-505054503030"]);
        Assert.Equal("Success", byGuid["0cce9235-69ae-11d9-bed3-505054503030"]);
        Assert.Equal("No Auditing", byGuid["0cce9248-69ae-11d9-bed3-505054503030"]);
        Assert.Equal("Failure", byGuid["0cce9237-69ae-11d9-bed3-505054503030"]);
        var names = (Dictionary<string, string>)ev["subcategory"]!;
        Assert.Equal("Grupo, con coma", names["0cce9237-69ae-11d9-bed3-505054503030"]);
    }

    [Fact]
    public void NoUsableRowsMeansNoBlock()
    {
        Assert.Null(AuditpolShape.ParseBackupCsv(null));
        Assert.Null(AuditpolShape.ParseBackupCsv("Machine Name,Policy Target\r\nPC1,System\r\n"));
        Assert.Null(AuditpolShape.ParseBackupCsv("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n"));
    }

    [Fact]
    public void UnknownSettingValueIsVisibleNotSilent()
    {
        Assert.Equal("Unknown(7)", AuditpolShape.SettingName(7));
    }
}
