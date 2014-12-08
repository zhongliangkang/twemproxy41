cmd='mset '
for i in range(9) :
    k=''
    v=''
    for j in range(462) :
       k += 'k' 
    cmd += "%s-%d %s-%d " % (k, i, v, i)
print cmd

