(* Lucrare de laborator nr. 5, varianta 1: RSA, ElGamal, Diffie-Hellman + AES-256
   Wolfram Mathematica.  Mesajul m = "Nume Prenume" (ASCII, fara diacritice).
   NOTA: acest fisier nu a putut fi rulat in Mathematica la scrierea lui;
   aceleasi calcule au fost executate si verificate in lab5_v1.py. *)

(* ---------- 0. Mesajul: caractere -> ASCII -> hex -> zecimal ---------- *)
msg   = "Catana Marin";
codes = ToCharacterCode[msg, "ASCII"];       (* coduri ASCII (zecimal) *)
hex   = StringJoin[IntegerString[codes, 16, 2]];   (* "436174616E61204D6172696E" *)
m     = FromDigits[hex, 16]                  (* 20853311054332600596810590574 *)
Length[IntegerDigits[m, 2]]                  (* 95 biti *)

(* ---------- 2.1 RSA (n de 2048 biti) ---------- *)
p = RandomPrime[{2^1023, 2^1024 - 1}];       (* prim de 1024 biti *)
q = RandomPrime[{2^1023, 2^1024 - 1}];
While[q == p, q = RandomPrime[{2^1023, 2^1024 - 1}]];
n   = p q;                                   (* modulul *)
Length[IntegerDigits[n, 2]]                  (* trebuie sa fie >= 2048 *)
phi = (p - 1) (q - 1);                       (* functia Euler *)
e   = 65537;                                 (* exponentul public *)
GCD[e, phi]                                  (* trebuie sa fie 1 *)
d   = PowerMod[e, -1, phi];                  (* exponentul secret: e*d = 1 mod phi *)
c   = PowerMod[m, e, n]                      (* criptare:   c = m^e mod n *)
m2  = PowerMod[c, d, n]                      (* decriptare: m = c^d mod n *)
m2 == m
FromCharacterCode[IntegerDigits[m2, 256]]   (* "Catana Marin" *)

(* ---------- 2.2 ElGamal ---------- *)
pp = 32317006071311007300153513477825163362488057133489075174588434139269806834136210002792056362640164685458556357935330816928829023080573472625273554742461245741026202527916572972862706300325263428213145766931414223654220941111348629991657478268034230553086349050635557712219187890332729569696129743856241741236237225197346402691855797767976823014625397933058015226858730761197532436467475855460715043896844940366130497697812854295958659597567051283852132784468522925504568272879113720098931873959143374175837826000278034973198552060607533234122603254684088120031105907484281003994966956119696956248629032338072839127039;          (* p din enunt, 2048 biti *)
g  = 2;
PrimeQ[pp]                                   (* True *)
x  = RandomInteger[{2, pp - 2}];             (* cheia privata *)
h  = PowerMod[g, x, pp];                     (* cheia publica h = g^x mod p *)
k  = RandomInteger[{2, pp - 2}];             (* numar aleator efemer *)
c1 = PowerMod[g, k, pp];                     (* c1 = g^k mod p *)
c2 = Mod[m PowerMod[h, k, pp], pp];          (* c2 = m * h^k mod p *)
s  = PowerMod[c1, x, pp];                    (* s = c1^x = h^k mod p *)
mE = Mod[c2 PowerMod[s, -1, pp], pp]         (* decriptare: m = c2 * s^-1 mod p *)
mE == m

(* ---------- 3. Diffie-Hellman + AES-256 ---------- *)
a  = RandomInteger[{2, pp - 2}];             (* secretul Alisei *)
b  = RandomInteger[{2, pp - 2}];             (* secretul lui Bob *)
A  = PowerMod[g, a, pp];                     (* Alisa trimite A *)
B  = PowerMod[g, b, pp];                     (* Bob trimite B *)
Ka = PowerMod[B, a, pp];                     (* cheia calculata de Alisa *)
Kb = PowerMod[A, b, pp];                     (* cheia calculata de Bob *)
Ka == Kb
(* cheia AES-256 = SHA-256 al lui K (256 octeti, big-endian) *)
keyHex = IntegerString[Hash[ByteArray[IntegerDigits[Ka, 256, 256]], "SHA256"], 16, 64]
keyObj = GenerateSymmetricKey[ByteArray[IntegerDigits[FromDigits[keyHex, 16], 256, 32]]];
ct = Encrypt[keyObj, msg];                   (* Alisa cripteaza *)
Decrypt[keyObj, ct]                          (* Bob decripteaza: "Catana Marin" *)
