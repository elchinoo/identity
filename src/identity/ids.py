from apgkit.ids import new_id


def new_user_id() -> str:
    return new_id("usr_", 16)


def new_kid() -> str:
    return new_id("k", 12)
