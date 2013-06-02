import re

def get_function_name(st):
    m = re.search(r"\(\*([A-Za-z0-9_]+)\)", st)
    return m.group(1)

def write_to_file(fp, content, current):
    if current != '':
        fp.write('fprintf(fp,"'+ content +' %ld\\n",ctx->'+current+'->'+content+');\n')
    else:
        fp.write('fprintf(fp,"'+ content +' %ld\\n",ctx->'+content+');\n')
    
def  main():
    fp = open("fpointers")
    fo = open("fpointers_out.txt","w")
    for line in fp.readlines():
        if line.strip() != '' and line[0] != '\t':
            parts = line.split()
            if len(parts) > 2:
                current = ''
                if '(*' in line:
                    write_to_file(fo, get_function_name(line), '')                    
            elif len(parts) == 2:
                current = line.split()[1]
            else:
                current = current +'->' + line.strip()
        elif line.strip() != '' and len(line.strip().split()) == 1:
            parts = current.split('->')
            if len(parts) > line.count('\t'):
                i=0
                current = ''
                while i < len(parts)-1:
                    if i != 0:
                        current += '->' + parts[i]
                    else:
                        current += parts[i]
                    i += 1
            current = current + '->' + line.strip()
            fo.write('\n')
        elif line.strip() != '':
            if '(*' in line:
                write_to_file(fo,get_function_name(line),current)
    
main()