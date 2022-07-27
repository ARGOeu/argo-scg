class MyException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return f"Error: {str(self.msg)}"


class SensuException(MyException):
    def __str__(self):
        return f"Sensu error: {str(self.msg)}"


class PoemException(MyException):
    def __str__(self):
        return f"Poem error: {str(self.msg)}"


class WebApiException(MyException):
    def __str__(self):
        return f"WebApi error: {str(self.msg)}"


class ConfigException(MyException):
    def __str__(self):
        return f"Error reading configuration file: {str(self.msg)}"


class GeneratorException(MyException):
    def __str__(self):
        return str(self.msg)
