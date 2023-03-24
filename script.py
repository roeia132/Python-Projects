def lines_count():
    file = open("file.txt", "r")
    lines = len(file.readlines())
    file.close()
    return lines


def check_let():
    file = open("file.txt", "r")
    lines = file.readlines()
    num_lines = 0
    final = ""
    for line in lines:
        num_lines += 1
        msg = []
        ls = line.split(":")[0].split(",")
        split_ls = line.split(":")
        numbers = split_ls[1]
        var = len(line.split(":")[0].split(","))
        for i in range(var):
            msg.append(ls[i][0].lower())
        new_var = "|".join(msg)
        new_var += "|" + "line#" + str(num_lines)

        sum1 = 0
        for n in numbers:
            try:
                sum1 += int(n)
            except:
                pass

        final += f"{new_var}|{sum1}\n"
    return final
