import { describe, expect, it } from "vitest";
import { normalizeSoftwareDisplayMetadata } from "../../src/domain/software-display-normalizer";

const receipt = (id: string) => normalizeSoftwareDisplayMetadata({ name: id, source: "pkgutil", packageFamilyName: id }).displayName;

describe("nombre de un recibo de pkgutil", () => {
  it("⭐ CLIFIJIMENEZlocal 30-sep: el fabricante no sale dos veces", () => {
    expect(receipt("com.microsoft.package.Microsoft_Excel.app")).toBe("Microsoft Excel");
    expect(receipt("com.microsoft.package.Microsoft_Word.app")).toBe("Microsoft Word");
  });

  it("sin repetición, el nombre no cambia", () => {
    expect(receipt("com.apple.pkg.Keynote14")).not.toMatch(/^(\S+) \1\b/i);
    expect(receipt("org.example.pkg.Report_Builder")).toBe("Example Report Builder");
  });

  it("sólo una palabra ENTERA repetida: «Micro Microsoft» no se toca", () => {
    expect(receipt("com.micro.Microsoft_Tool")).toBe("Micro Microsoft Tool");
  });
});
