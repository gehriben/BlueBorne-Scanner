def readFile():
    f = open("mac.txt","r")
    result = [line.rstrip('\n') for line in f]
    final = []
    for entry in result:
        temp = entry.split()
        final.append(temp)
    return final
