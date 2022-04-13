a = ""
for i in range(200):
    a += ("%" + str(i) + "$p").ljust(10)
print(a)
