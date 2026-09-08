import re

GOT_ROOT_REGEXPs = [re.compile("^# $"), re.compile("^bash-[0-9]+.[0-9]# $")]


def got_root(hostname: str, output: str) -> bool:
    for i in GOT_ROOT_REGEXPs:
        if i.fullmatch(output):
            return True

    # Match root@<any_hostname>: to handle Docker containers where
    # the container hostname differs from the connection hostname.
    if output.startswith(f"root@{hostname}:"):
        return True
    if re.match(r"^root@[\w.-]+:", output):
        return True

    return False
