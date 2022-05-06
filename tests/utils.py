class MockResponse:
    def __init__(self, data, status_code):
        self.data = data
        self.status_code = status_code
        self.reason = "BAD REQUEST"
        self.ok = False
        if str(status_code).startswith("2"):
            self.ok = True
            self.reason = "OK"

    def json(self):
        return self.data
