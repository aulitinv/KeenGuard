"""Keenetic hardware packet capture management mixin."""
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger("keenguard.keenetic.capture")


class KeeneticCaptureMixin:
    """Methods for managing on-router packet capture via RCI."""

    async def is_packet_capture_supported(self) -> bool:
        """
        Checks whether the router firmware supports hardware packet capture via RCI.
        Caches the result to avoid redundant network round-trips.
        """
        if getattr(self, "mock_mode", False):
            return True
        if self._capture_supported is not None:
            return self._capture_supported

        try:
            resp = await self._send_request("GET", "/rci/monitor/capture/interface")
            if resp is not None and resp.status_code in (200, 204):
                self._capture_supported = True
            elif resp is not None and resp.status_code in (400, 404, 501):
                self._capture_supported = False
            else:
                return False
        except Exception as e:
            logger.debug("Error checking packet capture support: %s", e)
            return False
        return bool(self._capture_supported)

    async def start_packet_capture(
        self,
        interface: str = "Bridge0",
        target_ip: Optional[str] = None,
        duration_seconds: int = 300,
        max_size_kb: int = 5120,
        buffer_size_kb: int = 512
    ) -> Optional[Dict[str, Any]]:
        """
        Configures and starts event-driven packet capture on Keenetic interface.
        BPF filter restricts capture strictly to target_ip if provided.
        """
        payload: Dict[str, Any] = {
            "name": interface,
            "enable": True,
            "capture-size": {"size-kb": max_size_kb},
            "buffer-size": {"size-kb": buffer_size_kb},
            "max-frame-size": {"size": 1518},
            "direction": "in-out",
            "timeout": {"timeout-ms": duration_seconds * 1000}
        }
        if target_ip:
            payload["filter"] = {"bpf-program": f"host {target_ip}"}

        logger.info(
            "Starting Keenetic hardware capture on %s (IP: %s, duration: %ds, max: %dKB)",
            interface, target_ip or "all", duration_seconds, max_size_kb
        )

        if getattr(self, "mock_mode", False):
            self._mock_captures[interface] = {
                "payload": payload,
                "file_path": f"capture_{interface}.pcap",
                "target_ip": target_ip,
                "is_running": True
            }
            return {"status": "ok", "interface": interface, "filter": payload.get("filter")}

        resp = await self._send_request("POST", "/rci/monitor/capture/interface", json_data=payload)
        if resp and resp.status_code in (200, 201, 204):
            return {"status": "ok", "interface": interface, "filter": payload.get("filter")}
        else:
            status = resp.status_code if resp else "no response"
            logger.warning("Keenetic hardware capture start failed on %s: HTTP %s", interface, status)
            return None

    async def stop_packet_capture(self, interface: str = "Bridge0") -> Optional[str]:
        """
        Stops packet capture on Keenetic interface and retrieves the relative capture file path.
        """
        logger.info("Stopping Keenetic hardware capture on %s", interface)
        if getattr(self, "mock_mode", False):
            info = self._mock_captures.get(interface, {})
            info["is_running"] = False
            return info.get("file_path", f"capture_{interface}.pcap")

        payload = {"name": interface, "enable": False}
        await self._send_request("POST", "/rci/monitor/capture/interface", json_data=payload)

        capture_file = None
        status_resp = await self._send_request("GET", "/rci/monitor/capture/interface")
        if status_resp and status_resp.status_code == 200:
            try:
                data = status_resp.json()
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if isinstance(item, dict) and item.get("name") == interface:
                        capture_file = item.get("captureFilePath") or item.get("file") or item.get("path") or item.get("capture-file")
                        break
            except Exception as e:
                logger.debug("Error parsing capture status JSON: %s", e)

        if not capture_file:
            capture_file = f"capture_{interface}.pcap"

        return capture_file

    async def download_capture_file(self, capture_file_path: str, local_dest_path: Path) -> bool:
        """
        Downloads a captured .pcap file from Keenetic router via /ci/<path> and saves locally.
        """
        local_dest_path = Path(local_dest_path)
        local_dest_path.parent.mkdir(parents=True, exist_ok=True)

        if getattr(self, "mock_mode", False):
            try:
                from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw
                pkts = [
                    Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") /
                    IP(src="192.168.1.105", dst="198.51.100.10") /
                    TCP(sport=54321, dport=80, flags="PA") /
                    Raw(load=b"GET /api/v1/telemetry HTTP/1.1\r\nHost: smart-tv-cloud.example.com\r\nUser-Agent: SmartTV/5.0\r\n\r\n"),
                    Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") /
                    IP(src="192.168.1.105", dst="192.168.1.1") /
                    UDP(sport=53535, dport=53) /
                    Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
                ]
                wrpcap(str(local_dest_path), pkts)
                return True
            except Exception as e:
                logger.error("Mock pcap generation failed: %s", e)
                header = bytes([
                    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00
                ])
                local_dest_path.write_bytes(header)
                return True

        if not self._cookies:
            auth = await self.authenticate()
            if auth.get("status") != "ok":
                return False

        clean_path = capture_file_path.strip().lstrip("/")
        url = f"/{clean_path}" if clean_path.startswith("ci/") else f"/ci/{clean_path}"

        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=30.0, verify=False) as client:
                resp = await client.get(url, cookies=self._cookies)
                if resp.status_code == 200 and len(resp.content) > 0:
                    local_dest_path.write_bytes(resp.content)
                    logger.info("Successfully downloaded router capture to %s (%d bytes)", local_dest_path, len(resp.content))
                    return True
                else:
                    logger.warning("Router capture download failed (HTTP %d, %d bytes)", resp.status_code, len(resp.content))
                    return False
        except Exception as e:
            logger.error("Failed to download capture file from %s: %s", url, e)
            return False

    async def reset_packet_capture(self, interface: str = "Bridge0") -> bool:
        """
        Resets packet capture state on Keenetic and frees allocated buffer memory on router.
        """
        logger.debug("Resetting Keenetic hardware capture on %s", interface)
        if getattr(self, "mock_mode", False):
            self._mock_captures.pop(interface, None)
            return True

        payload = {"name": interface, "enable": False, "reset": True}
        resp = await self._send_request("POST", "/rci/monitor/capture/interface", json_data=payload)
        return resp is not None and resp.status_code in (200, 204)

    async def cleanup_orphan_captures(self) -> None:
        """
        Resets and cleans up any lingering capture sessions on common router interfaces.
        """
        for iface in ("Bridge0", "Bridge1", "ISP"):
            try:
                await self.reset_packet_capture(iface)
            except Exception as e:
                logger.debug("Failed resetting packet capture on %s: %s", iface, e)
