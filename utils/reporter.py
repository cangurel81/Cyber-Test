class TestReporter:
    def __init__(self):
        self.results = []

    def add_result(self, test_name, status, message):
        self.results.append({
            "test_name": test_name,
            "status": "PASSED" if status else "FAILED",
            "message": message
        })

    def generate_report(self):
        report_str = "--- Test Report ---\n"
        for result in self.results:
            report_str += f"Test: {result['test_name']}\n"
            report_str += f"Status: {result['status']}\n"
            report_str += f"Message: {result['message']}\n"
            report_str += "--------------------\n"
        return report_str

    def clear_results(self):
        self.results = []