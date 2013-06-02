from curses.ascii import isalpha
def main():
    fp = open("Data_pointers")
    fo = open("Data_pointers_out","w")
    current_t = 0
    prev_t = 0
    for line in fp.readlines():
        if line.strip() == '' or '#' in line or '/*' in line or '*/' in line:
            continue
        if line[0] != '\t':
            parts = line.split()
            current = parts[-1].lstrip('*').rstrip(';')
            prev_t = 0
            continue
        current_t - 0
        i = 0
        s = line[i]
        while not isalpha(s):
            s = line[i]
            i += 1
        current_t = i
        tmp = current.replace('.','->')
        parts = tmp.split('->')
                
        if parts[-1] == '':
            parts = parts[:len(parts)-1];
        
        print current, line.strip(),parts    
            
        if not(current_t > prev_t) and len(parts) > current_t:
            print current_t
            diff = parts[(len(parts) - current_t) * -1]
            print diff
            pos = current.rfind(diff)
            if current[pos-1] == '>':
                current = current[:pos-2]
            else:
                current = current[:pos]
        parts = line.split()
        if ',' in parts[-1]:
            parts1 = parts[-1].split(',')
            pcurrent = current
            for p in parts1:
                if pcurrent[-1] != '.':
                    current = pcurrent + '->' + p.rstrip(';').lstrip('*')
                else:
                    current = pcurrent + p.rstrip(';').lstrip('*')
                fo.write(current+'\n')
        else:    
            if current[-1] != '.':
                current = current + '->' + parts[-1].rstrip(';').lstrip('*')
            else:
                current = current + parts[-1].rstrip(';').lstrip('*')
            fo.write(current+'\n')
                
        prev_t = current_t   
main()