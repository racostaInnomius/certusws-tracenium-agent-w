$ErrorActionPreference = "Stop"

$requiredFiles = @(
  "assets\tracenium.ico",
  "assets\wix-dialog.bmp",
  "assets\wix-banner.bmp",
  "binaries\AgentCore\TraceniumAgentCore.exe",
  "binaries\AgentCore\TraceniumAgentCore.xml",
  "binaries\AgentCore\node\node.exe",
  "binaries\AgentTray\Tracenium.AgentTray.exe",
  "binaries\PrivSvc\Tracenium.PrivSvc.Windows.exe"
)

foreach ($file in $requiredFiles) {
  if (-not (Test-Path $file)) {
    throw "Missing required MSI input: $file"
  }
}

wix build `
  wix\Product.wxs `
  wix\Files.wxs `
  wix\AgentCoreFiles.wxs `
  wix\PrivSvc.wxs `
  wix\UI.wxs `
  -ext WixToolset.Util.wixext `
  -ext WixToolset.UI.wixext `
  -culture en-US `
  -arch x64 `
  -bindpath (Get-Location).Path `
  -o Tracenium-Agent.msi
