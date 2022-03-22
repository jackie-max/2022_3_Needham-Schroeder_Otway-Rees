from Crypto.Util.number import *
from Crypto.Random import *
from Crypto.Cipher import AES
import os

#Предварительный этап
#Генерация долговременных секретных ключей
K_AT = os.urandom(16)
K_BT = os.urandom(16)
print("K_AT = ", K_AT)
print("K_BT = ", K_BT)

#Генерация случайных одноразовых чисел
N_A = get_random_bytes(16)
N_B = get_random_bytes(16)
print("N_A = ", N_A)
print("N_B = ", N_B)
print("__________________________________________________________________________________________________________________", '\n')

#Рабочий этап
A = get_random_bytes(16)
B = get_random_bytes(16)
print("Центр доверия: от A получено M_0 = ", '(', A, B, N_A, ')')

#Центр доверия формирует сообщение, на основании данных от A
#Происходит шифрование данных при помощи AES на ключе K_AT
E_K_AT = AES.new(K_AT, AES.MODE_ECB)
#Происходит шифрование данных при помощи AES на ключе K_BT
E_K_BT = AES.new(K_BT, AES.MODE_ECB)
K = os.urandom(16)
print("K = ", K)
M_1 = E_K_AT.encrypt(N_A + B + K + E_K_BT.encrypt(K + A))
print('Центр доверия: A получит сообщение M_1 :', M_1)
print("_______________________________________________________________________________", '\n')

message_for_A_from_T = E_K_AT.decrypt(M_1)
print("Значение N_A, полученное A: ", message_for_A_from_T[0:16])
if message_for_A_from_T[0:16] == N_A:
    print("A получил сообщение от центра доверия.")
    #Отправка участнику B сообщения, зашифрованного на ключе K_BT
    M_2 = E_K_BT.encrypt(K + A)
    print('A: B получит сообщение M_2 :', M_2)
    message_for_B = E_K_BT.decrypt(M_2)
    print("Значение ключа, полученное B: ", message_for_B[0:16])
    # Происходит шифрование данных при помощи AES на ключе K
    E_K_from_B = AES.new(message_for_B[0:16], AES.MODE_ECB)
    M_3 = E_K_from_B.encrypt(N_B)
    print('B: A получит сообщение M_3 :', M_3)
    message_for_A_from_B = E_K_from_B.decrypt(M_3)
    print("Значение N_B, полученное A: ", message_for_A_from_B[0:16])
    M_4 = E_K_from_B.encrypt(long_to_bytes(bytes_to_long(N_B)-1))
    print("M_4 = ", M_4)
    print("Отклик получен.")
    print("A и B получили общий секретный ключ K: ", K)
else:
    print("Число N_A не совпало с полученным от центра доверия. A не получил сообщение от центра доверия. Аутентификация провалена.")
