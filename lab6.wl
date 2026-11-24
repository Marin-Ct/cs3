(* Lucrare de laborator nr. 6: semnaturi digitale RSA si ElGamal
   k = 4  ->  i = (4 mod 24) + 1 = 5
   Sarcina 2: hash nr. 5 = MD6-256 ;  Sarcina 3: hash nr. 5 = MD6-128
   Mathematica NU are functia MD6 in Hash[], de aceea valorile hash (hex) se calculeaza
   cu md6.py (sau cu un calculator online MD6) si se introduc mai jos, apoi se transforma in zecimal.
   NOTA: acest fisier nu a fost rulat in Mathematica; aceleasi calcule au fost executate si verificate in lab6.py *)

hexMD6256 = "247247de2518d1a68068360bba082ea6399873bd59ed0e7eca949bc1211c4274";     (* MD6-256 al mesajului m din lucrarea 2 *)
hexMD6128 = "46acffb84170220a396c6572a6b23cf0";     (* MD6-128 al aceluiasi mesaj *)
h256 = FromDigits[hexMD6256, 16]   (* valoarea hash zecimala, sarcina 2 *)
h128 = FromDigits[hexMD6128, 16]   (* valoarea hash zecimala, sarcina 3 *)

(* ---------- Sarcina 2: semnatura RSA (n >= 3072 biti) ---------- *)
p = RandomPrime[{2^1535, 2^1536 - 1}];      (* prim de 1536 biti *)
q = RandomPrime[{2^1535, 2^1536 - 1}];
While[q == p, q = RandomPrime[{2^1535, 2^1536 - 1}]];
n   = p q;
Length[IntegerDigits[n, 2]]                    (* >= 3072 *)
phi = (p - 1) (q - 1);
e   = 65537;   GCD[e, phi]                     (* 1 *)
d   = PowerMod[e, -1, phi];                    (* cheia privata *)
s   = PowerMod[h256, d, n]                     (* semnarea: s = h^d mod n *)
w   = PowerMod[s, e, n]                        (* validarea: w = s^e mod n *)
w == h256                                      (* True -> semnatura valida *)

(* ---------- Sarcina 3: semnatura ElGamal ---------- *)
pp = 32317006071311007300153513477825163362488057133489075174588434139269806834136210002792056362640164685458556357935330816928829023080573472625273554742461245741026202527916572972862706300325263428213145766931414223654220941111348629991657478268034230553086349050635557712219187890332729569696129743856241741236237225197346402691855797767976823014625397933058015226858730761197532436467475855460715043896844940366130497697812854295958659597567051283852132784468522925504568272879113720098931873959143374175837826000278034973198552060607533234122603254684088120031105907484281003994966956119696956248629032338072839127039;
g  = 2;   PrimeQ[pp]
x  = RandomInteger[{2, pp - 2}];               (* cheia privata *)
y  = PowerMod[g, x, pp];                       (* cheia publica *)
k  = RandomInteger[{2, pp - 2}];
While[GCD[k, pp - 1] != 1, k = RandomInteger[{2, pp - 2}]];   (* gcd(k, p-1) = 1 *)
r  = PowerMod[g, k, pp];                       (* r = g^k mod p *)
sg = Mod[(h128 - x r) PowerMod[k, -1, pp - 1], pp - 1]    (* s = (h - x r) k^-1 mod (p-1) *)
(* validare: y^r * r^s = g^h (mod p) *)
Mod[PowerMod[y, r, pp] PowerMod[r, sg, pp], pp] == PowerMod[g, h128, pp]
