import socket

class GeneralServerTest:
    def __init__(self, target_ip, port=80):
        self.target_ip = target_ip
        self.port = port

    def test_connectivity(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, self.port))
            sock.close()
            if result == 0:
                return True, f"Port {self.port} is open."
            else:
                return False, f"Port {self.port} is closed or unreachable. Error code: {result}"
        except Exception as e:
            return False, f"Port scan failed on port {self.port}: {e}"

    def run_all_tests(self):
        results = []
        connected, msg = self.test_connectivity()
        results.append(("Connectivity Test", connected, msg))
        return results