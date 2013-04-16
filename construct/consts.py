
class ConstructLevel(object):
	__slots__=()

class GuestLevel(ConstructLevel):
	def __str__(self):
		return "guest"

class RegisteredLevel(ConstructLevel):
	def __str__(self):
		return "registered"

class ConfirmedLevel(ConstructLevel):
	def __str__(self):
		return "confirmed"

class OperLevel(ConstructLevel):
	def __str__(self):
		return "server operator"

# for profile's
guestlevel = GuestLevel()
registeredlevel = RegisteredLevel()
confirmedlevel = ConfirmedLevel()
operlevel = OperLevel()

# for channels
banrole = object()
allowrole = object()
operrole = object()

