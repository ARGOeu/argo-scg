class SCGException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


class SCGWarnException(SCGException):
    pass


class SensuException(SCGException):
    def __str__(self):
        return f"Sensu error: {str(self.msg)}"


class PoemException(SCGException):
    def __str__(self):
        return f"Poem error: {str(self.msg)}"


class WebApiException(SCGException):
    def __str__(self):
        return f"WebApi error: {str(self.msg)}"


class ConfigException(SCGException):
    def __str__(self):
        return f"Configuration file error: {str(self.msg)}"


class AgentConfigException(SCGException):
    def __str__(self):
        return f"Agent configuration file error: {str(self.msg)}"


class GeneratorException(SCGException):
    def __str__(self):
        return str(self.msg)
