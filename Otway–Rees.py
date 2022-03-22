from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Random import get_random_bytes
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

I = get_random_bytes(16)
print("I = ", I)
print("__________________________________________________________________________________________________________________", '\n')

#Рабочий этап
A = get_random_bytes(16)
B = get_random_bytes(16)
print("B: от A получено = ", '(', I, A, B, ')')

#Происходит шифрование данных при помощи AES на ключе A
E_A = AES.new(A, AES.MODE_ECB)
M_0 = I + A + B + E_A.encrypt(N_A + I + A + B)
print("B: от A получено = M_0", M_0)
print("__________________________________________________________________________________________________________________", '\n')

E_B = AES.new(B, AES.MODE_ECB)
M_1 = M_0 + E_B.encrypt(N_B + I + A + B)
print("B: M_1 = ", M_1)
print("__________________________________________________________________________________________________________________", '\n')

# mes = M_0[64:79]
# print(mes)
message_A = (M_0[48:128])
message_A_T = E_A.decrypt(message_A)
# print(message_A)
print("Центр доверия T: расшифрованное сообщение A: ", message_A_T)
I_A = message_A_T[16:32]
if I_A == I:
    print("Сессионные идентификаторы совпали.")
    print("I_A: ", I_A)

message_B = (M_1[112:256])
message_B_T = E_B.decrypt(message_B)
# print(message_B)
print("Центр доверия T: расшифрованное сообщение B: ", message_B_T)
I_B = message_B_T[16:32]
if I_B == I:
    print("Сессионные идентификаторы совпали.")
    print("I_B: ", I_B)

s = os.urandom(16)
print("Центр доверия T сгенерировал ключ s: ", s)
M_2 = E_A.encrypt(N_A + s) + E_B.encrypt(N_B + s)
print("Центр доверия T отправил участнику B: ", M_2)
print("__________________________________________________________________________________________________________________", '\n')

message_B_T = E_A.decrypt(M_2[0:32]) + E_B.decrypt(M_2[32:64])
print("B: от центра доверия получено и расшифровано сообщение: ", message_B_T)

M_3 = M_2[0:32]
print("A: получено сообщение: ", M_3)
message = E_A.decrypt(M_2)
K = message[16:32]

if K == s:
    print("A получил секретный ключ:", K)
    print("Участники A и B получили секретный ключ s. Аутентификация прошла успешно.")
else:
    print("Участники A и B не получили секретный ключ s. Аутентификация провалена.")
