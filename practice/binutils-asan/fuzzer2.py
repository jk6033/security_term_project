import os
from signal import alarm, signal, SIGALRM, SIGKILL
from subprocess import PIPE, Popen
import sys
from shutil import copyfile, rmtree
import random
import time

import minimizer

afl_path = '/home/crybaby26/security_term_project/practice/afl-2.52b' # 'path to afl'

prog_name = ''
prog_args = ''

output_dir = ''
seed_dir = ''

cur_file = ''

queue = []
queue_dir = ''
queue_id = 0
cur_queue_id = 0

crashes = []
crash_dir = ''
crash_id = 0

interest_list = [] # interesting values example

def is_new_crash(crash):
    print 'triage crashes.'

    return True

def crash_handler():
    global crash_id
    global cur_file

    if is_new_crash(cur_file):
        copyfile(cur_file, os.path.join(crash_dir, 'id_'+str(crash_id)))
        print 'new crash found! id: ' + str(crash_id)
        crash_id += 1

def run(args, cwd = None, shell = False, kill_tree = True, timeout = -1, env = None):
    '''
    Run a command with a timeout after which it will be forcibly
    killed.
    '''
    class Alarm(Exception):
        pass
    def alarm_handler(signum, frame):
        raise Alarm
    
    p = Popen(args, shell = shell, cwd = cwd, stdout = PIPE, stderr = PIPE, env = env)
    
    if timeout != -1:
        signal(SIGALRM, alarm_handler)
        alarm(timeout)
    try:
        stdout, stderr = p.communicate()
        if timeout != -1:
            alarm(0)
    except Alarm:
        pids = [p.pid]
        if kill_tree:
            pids.extend(get_process_children(p.pid))
        for pid in pids:
            # process might have died before getting to this line
            # so wrap to avoid OSError: no such process
            try: 
                os.kill(pid, SIGKILL)
            except OSError:
                pass
        return -9, '', ''

    if (p.returncode-128 == 11) or (p.returncode-128 == 6):         # Segmentation fault=11, Abort=6
        return -1

    return 0

    #return p.returncode

# utility function for mutation
def extend_bit(bitString):
    temp = bitString[2:]
    extend = 8 - len(temp)
    result = "0b" + str(0)*extend + temp
    return result

def mutate(orig_file):
    global cur_file

    if os.path.isfile(cur_file):
        os.remove(cur_file)
    
    fin = open(os.path.join(queue_dir, orig_file), 'rb')
    fout = open(cur_file, 'wb')

    orig_data = fin.read()
    
    in_size = len(orig_data)                                # input size

    mutation_count = random.randrange(1, 100)               # mutate n times

    mutate_data = orig_data

    for j in range(mutation_count):                         
        offset_to_mutate = random.randrange(0, in_size)     # offset to mutate
        rand_size = random.randrange(1, 16)
        strategy = random.randrange(0, 7)

        if strategy == 0:                                   # random byte mutation
            print 'mutation strategy 0.'
            temp = mutate_data[:offset_to_mutate]
        
            for i in range(rand_size):                      # mutate size 1-4
                temp += chr(random.randrange(0, 1114112))

            temp += mutate_data[offset_to_mutate+rand_size:]
            
            mutate_data = temp

        elif strategy == 1:                                 # bit flipping
            print 'mutation strategy 1.'
            '''
            Walking bit flips: 
            the first and most rudimentary strategy employed by afl involves performing sequential, ordered bit flips. 
            The stepover is always one bit; the number of bits flipped in a row varies from one to four. 
            '''
            temp = ""
            for m in mutate_data:
                flipped = ""
                byte = extend_bit(m)
                flip_size = random.randrange(1, 5)
                for f in range(flip_size):
                    if int(byte[f+2]): flipped += str(0)
                    else: flipped += str(1)
                byte = byte[:2] + flipped + byte[2+flip_size:]
                temp += chr(int(byte, 2))
            
            mutate_data = temp

        elif strategy == 2:
            print 'mutation strategy 2.'                    # byte flipping    
            '''
            Walking byte flips: 
            a natural extension of walking bit flip approach, 
            this method relies on 8-bit wide bitflips with a constant stepover of one byte. 
            '''
            temp = ""
            for m in mutate_data:
                flipped = ""
                byte = extend_bit(m)
                flip_size = 8
                for f in range(flip_size):
                    if int(byte[f+2]): flipped += str(0)
                    else: flipped += str(1)
                byte = byte[:2] + flipped + byte[2+flip_size:]
                temp += chr(int(byte, 2))
            
            mutate_data = temp

        elif strategy == 3:                          
            print 'mutation strategy 3.'                    # arithmetic inc/dec
            '''
            Simple arithmetics: 
            to trigger more complex conditions in a deterministic fashion, 
            the third stage employed by afl attempts to subtly increment or decrement existing integer values in the input file; 
            this is done with a stepover of one byte. The experimentally chosen range for the operation is -35 to +35; past these bounds, fuzzing yields drop dramatically. 
            In particular, the popular option of sequentially trying every single value for each byte (equivalent to arithmetics in the range of -128 to +127) helps very little and is skipped by afl.
            
            When it comes to the implementation, the stage consists of three separate operations. 
            First, the fuzzer attempts to perform subtraction and addition on individual bytes. 
            With this out of the way, the second pass involves looking at 16-bit values, using both endians 
            - but incrementing or decrementing them only if the operation would have also affected the most significant byte 
            (otherwise, the operation would simply duplicate the results of the 8-bit pass). 
            The final stage follows the same logic, but for 32-bit integers.
            '''
            
            pass

        elif strategy == 4:                          
            print 'mutation strategy 4.'                    # interesting value
            '''
            Known integers: 
            the last deterministic approach employed by afl relies on a hardcoded set of integers chosen for their demonstrably elevated likelihood of triggering edge conditions in typical code (e.g., -1, 256, 1024, MAX_INT-1, MAX_INT). 
            The fuzzer uses a stepover of one byte to sequentially overwrite existing data in the input file with one of the approximately two dozen "interesting" values, using both endians (the writes are 8-, 16-, and 32-bit wide).
            '''
            pass

        elif strategy == 5:                          
            print 'mutation strategy 5.'                    # block insertion: 1 block = 16 bytes
            pass
 
        elif strategy == 6:                          
            print 'mutation strategy 6.'                    # block deletion : 1 block = 16 bytes
            pass

        print mutate_data
        # more strategy
    

    fout.write(mutate_data)

    fin.close()
    fout.close()

def get_process_children(pid):
    p = Popen('ps --no-headers -o pid --ppid %d' % pid, shell = True,
              stdout = PIPE, stderr = PIPE)
    stdout, stderr = p.communicate()
    return [int(p) for p in stdout.split()]

def init_queue(dir):
    global queue_id

    print ''

    files = os.listdir(dir)

    for f in files:
        if f[0] != '.':
            temp_name = 'id_' + str(queue_id) + '_' + f
            queue.append(temp_name)
            copyfile(os.path.join(dir, f), os.path.join(queue_dir, 'id_' + str(queue_id) + '_' + f))
            queue_id += 1
            
            # print f

    pass

def add_interesting(file):
    global queue_id

    temp_name = 'id_' + str(queue_id) 
    queue.append(temp_name)
    copyfile(file, os.path.join(queue_dir, temp_name))

    queue_id += 1

    print 'new testcase found! ' + temp_name

if __name__ == '__main__':
    prog_name = sys.argv[1]

    if len(sys.argv) >= 5:
        prog_args = sys.argv[2]
        seed_dir = sys.argv[3]
        output_dir = sys.argv[4]

        cur_file = os.path.join(output_dir, 'cur_input')
        queue_dir = os.path.join(output_dir, 'queue')
        crash_dir = os.path.join(output_dir, 'crashes')

    else:
        print 'usage: ./fuzzer.py [prog_name] [prog_args] [seed_dir] [output_dir]'
        exit()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    else:
        rmtree(output_dir)
        os.makedirs(output_dir)
        #print 'output directory already exist!'
        #exit()

    os.makedirs(queue_dir)
    os.makedirs(crash_dir)

    print 'target program: ' + prog_name
    print 'program argument: ' + prog_args
    print 'seed dir: ' + seed_dir

    init_queue(seed_dir)

    cmd = prog_name + ' ' + prog_args

    minimizer_ = minimizer.TestcaseMinimizer(cmd.split(' '), afl_path, output_dir)

    os.environ['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1'

    while True:
        s = queue[random.randrange(0, len(queue))]

        print 'cur_input: ' + s

        for i in range(100):           # mutate 100 times for a test case

            mutate(s)
            
            cmd = prog_name + ' ' + prog_args
            cmd = cmd.replace('@@', cur_file)

            # -1: crash, 1: interesting
            result = run(cmd, shell = True, timeout = 1)

            if result == -1:
                crash_handler()

            if minimizer_.check_testcase(cur_file):
                add_interesting(cur_file)