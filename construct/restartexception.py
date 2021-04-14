

class RestartException(Exception):
    """ thrown to force full restart """

    def __init__(self):
        super(RestartException, self).__init__("restart exception")
