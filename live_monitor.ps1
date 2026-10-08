$project = "C:\Users\HP\OneDrive\Desktop\New folder\Packet_analyzer"

$dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"

$dpi = "$project\dpi_simple.exe"

while ($true) {

    Write-Host ""
    Write-Host "========================================"
    Write-Host "        LIVE DPI MONITORING"
    Write-Host "========================================"
    Write-Host ""

    Write-Host "[1] Capturing Wi-Fi traffic for 30 seconds..."

    & $dumpcap `
        -i 4 `
        -a duration:30 `
        -F pcap `
        -w "$project\live.pcap"

    Write-Host ""
    Write-Host "[2] Processing traffic with DPI engine..."

    & $dpi `
        "$project\live.pcap" `
        "$project\live_output.pcap"

    Write-Host ""
    Write-Host "[3] traffic.csv updated."
    Write-Host ""
    Write-Host "Starting next capture in 2 seconds..."

    Start-Sleep -Seconds 2
}
