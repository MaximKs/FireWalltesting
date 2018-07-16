from scapy.all import *
import paramiko
import datetime
import time
from termcolor import colored


def parser(string):
    PIP = IP()
    PEther = Ether()
    PTCP = TCP()
    PUDP = UDP()
    PICMP = ICMP()

    ether_flag = False
    ip_flag = False
    tcp_flag = False
    udp_flag = False
    icmp_flag = False

    rule = string
    forward_flag = False
    input_flag = False
    print(rule)
    index_of_word = rule.find('forward')
    if index_of_word >= 0:
        rule = rule[index_of_word + 8:]
        forward_flag = True

    else:
        index_of_word = rule.find('input')
        rule = rule[index_of_word + 6:]
        input_flag = True
    if input_flag:
        PIP.dst = ipfw
        PEther.dst = MACFW

    elif forward_flag:
        PIP.dst = ippc
        PEther.dst = MACPC

# -------------------------------------Eth-------------------------------------
    if 'ether' in rule:
        ether_flag = True

        if 'ether daddr' in rule:
            index_of_word = rule.find('daddr')
            PEther.dst = rule[index_of_word+6:index_of_word+23]

        if 'ether saddr' in rule:
            index_of_word = rule.find('saddr')
            PEther.src = rule[index_of_word + 6:index_of_word + 23]

        index_of_word = rule.find('ether type')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word+11:]
            index_of_word = temp_rule.find(' ')
            PEther.type = int(temp_rule[0:index_of_word], 0)
# -------------------------------------IP-------------------------------------
    if 'ip' in rule:
        ip_flag = True

        index_of_word = rule.find('ip daddr')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 9:]
            index_of_word = temp_rule.find(' ')
            index_of_word_mask = temp_rule.find('/32')
            if index_of_word_mask > 0:
                PIP.dst = temp_rule[0:index_of_word_mask]
            elif temp_rule.find('/') < 0:
                PIP.dst = temp_rule[0:index_of_word]

        index_of_word = rule.find('ip saddr')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 9:]
            index_of_word = temp_rule.find(' ')
            index_of_word_mask = temp_rule.find('/32')
            if index_of_word_mask > 0:
                PIP.src = temp_rule[0:index_of_word_mask]
            elif temp_rule.find('/') < 0:
                PIP.src= temp_rule[0:index_of_word]

        if 'protocol icmp' in rule:
            PIP.proto = 'icmp'
        elif 'protocol tcp' in rule:
            PIP.proto = 'tcp'
        elif 'protocol udp' in rule:
            PIP.proto = 'udp'
        elif 'protocol l2tp' in rule:
           PIP.proto = 115
        elif 'protocol ipv6' in rule:
            PIP.proto = 41
        elif 'protocol vrrp' in rule:
            PIP.proto = 112
        else:
            index_of_word = rule.find('protocol')
            if index_of_word >= 0:
                temp_rule = rule
                temp_rule = temp_rule[index_of_word + 9:]
                index_of_word = temp_rule.find(' ')
                command = temp_rule[0:index_of_word]
                PIP.proto = command

        index_of_word = rule.find('dscp')
        if index_of_word >= 0:
            if 'dscp cs1' in rule:
                PIP.tos = 32
            elif 'dscp af11' in rule:
                PIP.tos = 40
            elif 'dscp cs0' in rule:
                PIP.tos = 0
            elif 'dscp af12' in rule:
                PIP.tos = 48
            elif 'dscp af13' in rule:
                PIP.tos = 56
            elif 'dscp cs2' in rule:
                PIP.tos = 64
            elif 'dscp af21' in rule:
                PIP.tos = 72
            elif 'dscp af22' in rule:
                PIP.tos = 80
            elif 'dscp af23' in rule:
                PIP.tos = 88
            elif 'dscp cs3' in rule:
                PIP.tos = 96
            elif 'dscp af31' in rule:
                PIP.tos = 104
            elif 'dscp af32' in rule:
                PIP.tos = 112
            elif 'dscp af33' in rule:
                PIP.tos = 120
            elif 'dscp cs4' in rule:
                PIP.tos = 128
            elif 'dscp af41' in rule:
                PIP.tos = 136
            elif 'dscp af42' in rule:
                PIP.tos = 144
            elif 'dscp af43' in rule:
                PIP.tos = 152
            elif 'dscp cs5' in rule:
                PIP.tos = 160
            elif 'dscp ef' in rule:
                PIP.tos = 184
            elif 'dscp cs6' in rule:
                PIP.tos = 192
            elif 'dscp cs7' in rule:
                PIP.tos = 224


        index_of_word = rule.find('ecn')
        if index_of_word >= 0:
            if 'ecn ect0' in rule:
                PIP.tos = PIP.tos + 2
            elif 'ecn ect1' in rule:
                PIP.tos = PIP.tos + 1
            elif 'ecn ce' in rule:
                PIP.tos = PIP.tos + 3

        index_of_word = rule.find('ttl')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 4:]
            index_of_word = temp_rule.find(' ')
            PIP.ttl = int(temp_rule[0:index_of_word])

        index_of_word = rule.find('length')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 7:]
            index_of_word = temp_rule.find(' ')
            PIP.len = int(temp_rule[0:index_of_word])

# -------------------------------------TCP-------------------------------------
    index_of_word = rule.find('protocol tcp')
    if index_of_word >= 0:
        rule = rule[index_of_word+13:]
    if 'tcp' in rule:
        tcp_flag = True
        ip_flag = True
        index_of_word = rule.find('sport')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 6:]
            index_of_word = temp_rule.find(' ')
            PTCP.sport = int(temp_rule[0:index_of_word])

        index_of_word = rule.find('dport')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 6:]
            index_of_word = temp_rule.find(' ')
            PTCP.dport = int(temp_rule[0:index_of_word])

        index_of_word = rule.find('sequence')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 9:]
            print(temp_rule)
            index_of_word = temp_rule.find(' ')
            PTCP.seq = int(temp_rule[0:index_of_word])

        index_of_word = rule.find('ackseq')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 7:]
            index_of_word = temp_rule.find(' ')
            PTCP.ack = int(temp_rule[0:index_of_word])

        index_of_word = rule.find('flags')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 6:]
            index_of_word = temp_rule.find(' ')
            letter = temp_rule[0]
            if letter == 'c':
                PTCP.flags = 128
            elif letter == 'e':
                PTCP.flags = 64
            elif letter == 'u':
                PTCP.flags = 32
            elif letter == 'a':
                PTCP.flags = 16
            elif letter == 'p':
                PTCP.flags = 8
            elif letter == 'r':
                PTCP.flags = 4
            elif letter == 's':
                PTCP.flags = 2
            elif letter == 'f':
                PTCP.flags = 1

        index_of_word = rule.find('window')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 7:]
            index_of_word = temp_rule.find(' ')
            PTCP.window = int(temp_rule[0:index_of_word])

# -------------------------------------UDP-------------------------------------
    index_of_word = rule.find('protocol udp')
    if index_of_word >= 0:
        rule = rule[index_of_word+13:]
    if 'udp' in rule:
        udp_flag = True
        ip_flag = True
        index_of_word = rule.find('dport')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 6:]
            index_of_word = temp_rule.find(' ')
            PUDP.dport = int(temp_rule[0:index_of_word])

        index_of_word = rule.find('sport')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 6:]
            index_of_word = temp_rule.find(' ')
            PUDP.sport = int(temp_rule[0:index_of_word])

        index_of_word = rule.find('udp length')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 11:]
            index_of_word = temp_rule.find(' ')
            PUDP.len = int(temp_rule[0:index_of_word])

# ------------------------------------ICMP-------------------------------------
    index_of_word = rule.find('protocol icmp')
    if index_of_word >= 0:
        rule = rule[index_of_word+14:]

    if 'icmp' in rule:
        icmp_flag = True
        ip_flag = True
        index_of_word = rule.find('icmp type')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 10:]
            index_of_word = temp_rule.find(' ')
            command = temp_rule[0:index_of_word]
            if 'destination-unreachable' in command:
                 PICMP.type = 3
            elif 'info-request'in command:
                PICMP.type = 15
            elif 'info-reply'in command:
                PICMP.type = 16
            else:
                PICMP.type = command

        index_of_word = rule.find('icmp code')
        if index_of_word >= 0:
            temp_rule = rule
            temp_rule = temp_rule[index_of_word + 10:]
            index_of_word = temp_rule.find(' ')
            PICMP.code = int(temp_rule[0:index_of_word])


# ------------------------------------Packet-------------------------------------
    packet = ''

    if ether_flag == True and ip_flag == True and tcp_flag == True and udp_flag == False and icmp_flag == False :
        packet = PEther/PIP/PTCP
        print('Sending Ether/IP/TCP packet')
        send(packet)

    elif ether_flag == True and ip_flag == True and tcp_flag == False and udp_flag == True and icmp_flag == False :
        packet = PEther/PIP/PUDP
        print('Sending Ether/IP/UDP packet')
        send(packet)

    elif ether_flag == True and ip_flag == True and tcp_flag == False and udp_flag == False and icmp_flag == True :
        packet = PEther/PIP/PICMP
        print('Sending Ether/IP/ICMP packet')
        send(packet)

    elif ether_flag == True and ip_flag == True and tcp_flag == False and udp_flag == False and icmp_flag == False :
        packet = PEther/PIP
        print('Sending Ehter/IP packet')
        send(packet)

    elif ether_flag == False and ip_flag == True and tcp_flag == True and udp_flag == False and icmp_flag == False :
        packet = PIP/PTCP
        print('Sending IP/TCP packet')
        send(packet)

    elif ether_flag == False and tcp_flag == False and udp_flag == True and icmp_flag == False :
        packet = PIP/PUDP
        print('Sending IP/UDP packet')
        send(packet)

    elif ether_flag == False and tcp_flag == False and udp_flag == False and icmp_flag == True :
        packet = PIP/PICMP
        print('Sending IP/ICMP packet')
        send(packet)

    elif ether_flag == True and tcp_flag == False and udp_flag == False and icmp_flag == False :
        packet = PEther
        print('Sending Ether packet')
        send(packet)

    elif ether_flag == False and ip_flag == True and tcp_flag == False and udp_flag == False and icmp_flag == False :
        packet = PIP
        print('Sending IP packet')
        send(packet)
    print(list(packet))

    time.sleep(1)


def add_all_rules():
    delete_all_rules()
    with open('COMMAND.txt', 'r') as file, \
            open('ERROR.txt', 'w') as error_file, \
            open('LOG.txt', 'a') as log_file:
        count_of_commands = 0
        for line in file:
            if 'nft' in line:
                count_of_commands += 1
                stdin, stdout, stderr = client.exec_command(line + '>\&1')
                for i in stderr:
                    error_file.write(i)
                    log_file.write(i)
    return count_of_commands


def test(line):
    line_file = line
    parser(line_file)
    with open('RESULT.txt', 'a') as result_file:
        result_file.write(line_file)
        stdin, stdout, stderr = client.exec_command('nft list table filter -a')
        for line2 in stdout:
            temp_line2 = line2
            index_handle = temp_line2.find('handle')
            if index_handle >= 0:
                index_packets = temp_line2.find('packets')
                index_bytes = temp_line2.find('bytes')
                packets_line = temp_line2[index_packets + 8:]
                bytes_line = temp_line2[index_bytes + 6:]
                index_space_packets = packets_line.find(' ')
                index_space_byte = bytes_line.find(' ')
                packets = int(packets_line[0:index_space_packets])
                byt = int(bytes_line[0:index_space_byte])
                if packets > 0:
                    result_file.write(' packets = ' + str(packets) + ' bytes = ' + str(byt) + ' Ok\n')
                    print(colored('[          Packet was delivered to FW            ]', 'green'))
                else:
                    result_file.write(' packets = ' + str(packets) + ' bytes = ' + str(byt) + ' error\n')
                    print(colored('[        Packet was NOT delivered to FW          ]', 'red'))


def test_all():
    with open('RESULT.txt', 'w') as log:
        log.write('')
    with open('COMMAND.txt', 'r') as file, \
        open('ERROR.txt', 'w') as file_error, \
        open('LOG.txt', 'a') as log_error:
        for line in file:
            delete_all_rules()
            if 'nft' in line:
                stdin, stdout, stderr = client.exec_command(line + '>\&1')
                for i in stderr:
                    file_error.write(i)
                    log_error.write(i)
                stdin, stdout, stderr = client.exec_command('nft list table filter -a')
                for line2 in stdout:
                    if 'handle' in line2:
                        test(line)
        log_error.write('***-----------------' + str(datetime.datetime.now()) + '-----------------***' + '\n\n\n\n')


def delete_all_rules():
    stdin = client.exec_command('nft flush table filter')
    print('\nDone!')


def show_all_rules():
    stdin, stdout, stderr = client.exec_command('nft list table filter -a')
    count_of_rules = 0
    count_of_input_rules = 0
    count_of_forward_rules = 0
    count_of_output_rules = 0
    flag = 0
    for line in stdout:
        if 'chain input' in line:
            flag = 1
        elif 'chain forward' in line:
            flag = 2
        elif 'chain output' in line:
            flag = 3
        if 'handle' in line:
            count_of_rules += 1
            if flag == 1:
                count_of_input_rules += 1
            elif flag == 2:
                count_of_forward_rules += 1
            elif flag == 3:
                count_of_output_rules += 1
        print(line, end='')
    print('_____________________________________________________________')
    print('Amount of rules = ', count_of_rules,
          ', amount of inputs = ', count_of_input_rules,
          ', amount of forward = ', count_of_forward_rules,
          ', amount of outputs = ', count_of_output_rules,
          ', count of last new commands = ', count_of_commands)
    count = 0
    sh_error = u'sh: '
    nft_error = u'<cmdline>:'
    with open('ERROR.txt', 'r') as log_error_session:
        for line in log_error_session:
            if (sh_error in line) or (nft_error in line):
                count += 1
    print('count of wrong commands in last session = ', count)


def clear_log():
    with open('LOG.txt', 'w') as log:
        log.write('')
    print('\nLOG file clear -- DONE')


def help_menu():
    print('''
    Option              Meaning
    _____________________________________________________________
    ls                  Show all filters
    all                 Add all filters from COMMAND.txt
    rmall               Delete all filters from FW
    rmlog               Clear log file
    testall             Test all rules from COMMAND.txt
    exit                For exit
    ''')

parametrs = []

with open('CONFIG.txt', 'r') as config:
    for line in config:
        parametrs.append(line[:-1])

pre_host = list(parametrs[0])
pre_user = list(parametrs[1])
pre_secret = list(parametrs[2])
pre_port = list(parametrs[3])
pre_ippc = list(parametrs[4])
pre_ipfw = list(parametrs[5])
pre_MACPC = list(parametrs[6])
pre_MACFW = list(parametrs[7])

host = ''.join(pre_host[6:])
user = ''.join(pre_user[6:])
secret = ''.join(pre_secret[6:])
port = int(''.join(pre_port[6:]))
ippc = ''.join(pre_ippc[6:])
ipfw = ''.join(pre_ipfw[6:])
MACPC = ''.join(pre_MACPC[7:])
MACFW = ''.join(pre_MACFW[7:])

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(hostname=host, username=user, password=secret, port=port)

print('\n...connection enabled')


help_menu()
count_of_commands = 0
while True:
    com = input('Enter what to do:\t')
    if com == 'all':
        count_of_commands = add_all_rules()
    elif com == 'help':
        help_menu()
    elif com == 'rmall':
        delete_all_rules()
    elif com == 'ls':
        show_all_rules()
    elif com == 'rmlog':
        clear_log()
    elif com == 'exit':
        break
    elif com == 'testall':
        test_all()
    else:
        print(com + ' UNKNOWN COMMAND')
client.close()
print('Disconnect')