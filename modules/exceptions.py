class MyException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "Error: {}".format(str(self.msg))


class SensuException(MyException):
    def __str__(self):
        return "Sensu error: {}".format(str(self.msg))


class PoemException(MyException):
    def __str__(self):
        return "Poem error: {}".format(str(self.msg))


class WebApiException(MyException):
    def __str__(self):
        return "WebApi error: {}".format(str(self.msg))


class ConfigException(MyException):
    def __str__(self):
        return "Error reading configuration file: {}".format(str(self.msg))
