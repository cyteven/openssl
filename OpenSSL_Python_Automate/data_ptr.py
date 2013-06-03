from curses.ascii import isalpha

def prefix_tab(string):
    if string.strip() == '':
        return 0
    i = 0
    s = string[i]
    while not isalpha(s) and i < len(string):
        s = string[i]
        i += 1        
    return i

def main():
    fp = open("Data_pointers")
    fo = open("Data_pointers_out","w")
    current_t = 0
    prev_t = 0
    lines = fp.readlines()
    ii = 0
    while ii < len(lines):
        line = lines[ii]
        if line.strip() == '' or '#' in line or '/*' in line or '*/' in line:
            ii += 1
            continue
        if line[0] != '\t':
            parts = line.split()
            current = parts[-1].lstrip('*').rstrip(';')
            prev_t = 0
            ii += 1
            fo.write('fprintf(fp,"%ld\\n",ctx->'+current+');\n')
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
        
        #print current, line.strip(),parts    
            
        if not(current_t > prev_t) and len(parts) > current_t:
            #print current_t
            diff = parts[(len(parts) - current_t) * -1]
            #print diff
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
                if current[-1] != '.':
                    #fo.write(current+'\n')
                    fo.write('fprintf(fp,"%ld\\n",ctx->'+current+');\n')
                    #print current
        else:    
            if current[-1] != '.':
                current = current + '->' + parts[-1].rstrip(';').lstrip('*')
            else:
                current = current + parts[-1].rstrip(';').lstrip('*')
            if current[-1] != '.':
                    if ii < len(lines) - 1 and prefix_tab(lines[ii]) < prefix_tab(lines[ii+1]): 
                        #fo.write(current+'\n')
                        fo.write('fprintf(fp,"%ld\\n",ctx->'+current+');\n')
                        #print current
                    elif ii > len(lines) - 1:
                        #fo.write(current+'\n')
                        fo.write('fprintf(fp,"%ld\\n",ctx->'+current+');\n')
                        #print current
        prev_t = current_t
        ii += 1   
main()