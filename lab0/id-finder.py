s = 0
keys = dict()
p = 31
m= 2 ** 20

for first in range(1,27):
    res1 = first * p ** 0
    s += res1
    for second in range(1, 27):
        res2 = second * p ** 1
        s += res2
        for third in range(1, 27):
            res3 =  third * p ** 2
            s +=res3
            for fourth in range(1, 27):
                res4 = fourth * p ** 3
                s += res4
                for fifth in range(1, 27):
                    res5 = fifth * p ** 4
                    s += res5
                    key = s % m
                    current_value = (first, second, third, fourth, fifth, key)
                    if key in keys:
                        print("found a match!!")
                        print(keys[key])
                        print(current_value)
                        break
                    keys[key] = current_value
                    s -= res5
                s -= res4
            s-= res3
        s -= res2
    s-= res1


