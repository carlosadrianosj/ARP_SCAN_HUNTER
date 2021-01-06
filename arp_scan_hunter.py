#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from scapy.all import ARP, Ether, srp
import os, time
os.system('clear')

print ('\033[35m'+'''


   ▄████████    ▄████████    ▄███████▄         ▄████████  ▄████████    ▄████████ ███▄▄▄▄   
  ███    ███   ███    ███   ███    ███        ███    ███ ███    ███   ███    ███ ███▀▀▀██▄ 
  ███    ███   ███    ███   ███    ███        ███    █▀  ███    █▀    ███    ███ ███   ███ 
  ███    ███  ▄███▄▄▄▄██▀   ███    ███        ███        ███          ███    ███ ███   ███ 
▀███████████ ▀▀███▀▀▀▀▀   ▀█████████▀       ▀███████████ ███        ▀███████████ ███   ███ 
  ███    ███ ▀███████████   ███                      ███ ███    █▄    ███    ███ ███   ███ 
  ███    ███   ███    ███   ███                ▄█    ███ ███    ███   ███    ███ ███   ███ 
  ███    █▀    ███    ███  ▄████▀            ▄████████▀  ████████▀    ███    █▀   ▀█   █▀  
               ███    ███                                                                  
             ▄█    █▄    ███    █▄  ███▄▄▄▄       ███        ▄████████    ▄████████        
            ███    ███   ███    ███ ███▀▀▀██▄ ▀█████████▄   ███    ███   ███    ███        
            ███    ███   ███    ███ ███   ███    ▀███▀▀██   ███    █▀    ███    ███        
           ▄███▄▄▄▄███▄▄ ███    ███ ███   ███     ███   ▀  ▄███▄▄▄      ▄███▄▄▄▄██▀        
          ▀▀███▀▀▀▀███▀  ███    ███ ███   ███     ███     ▀▀███▀▀▀     ▀▀███▀▀▀▀▀          
            ███    ███   ███    ███ ███   ███     ███       ███    █▄  ▀███████████        
            ███    ███   ███    ███ ███   ███     ███       ███    ███   ███    ███        
            ███    █▀    ████████▀   ▀█   █▀     ▄████▀     ██████████   ███    ███        
                                                                         ███    ███        
                            
                            
                            (programador: carlosadrianosj)
(Ferramenta criada para enumeração de dispositivos na rede, utilizando protocolo ARP)

\n\n\n\n
''')

#verificação para determinar se o usuario esta em modo root
permissão_do_usuario = os.geteuid()
if permissao_do_usuario != 0:
    for i in range(5):
        print("              Este programa precisa ser executado em modo ROOT!!\n\n")
        time.sleep(0.5)        
    print("                 Exemplo: sudo python3 lazy_nmap_hunter.py")
    os._exit(0)      
else:
    pass

# Endereço IP para o destino
alvo_rede = str(input("Digite a range do IP ex(192.168.0.0/24): "))

# criar pacote ARP
arp = ARP(pdst=alvo_rede)

# criar o pacote de transmissão Ether
# endereço MAC (ff: ff: ff: ff: ff: ff) indica transmissão broadcast
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

# Monta o pacote
pacote = ether/arp
result = srp(pacote, timeout=3, verbose=0)[0]

# criando a lista a baixo vazia, pois vai ser preenchida com os hosts que serão encontrados
dispositivos_na_rede = []

for enviado, recebido in result:
    # para cada resposta, anexa o endereço ip e o mac à lista de dispositivos conectados na rede 
    dispositivos_na_rede.append({'ip': recebido.psrc, 'mac': recebido.hwsrc})

# printa os dispositivos que estão conectados na rede
print("  \n\n  Dispositivos conectados na Rede\n")
print("    IP" + " "*18+"    MAC")
for client in dispositivos_na_rede:
    print("{:16}    {}".format(client['ip'], client['mac']))

#comando serve para reiniciar as placas de rede ao terminar o scan, geralmente elas bugam e ficam inoperante
time.sleep(2)
os.system('sudo systemctl restart NetworkManager.service')
