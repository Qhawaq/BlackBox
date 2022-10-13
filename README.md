## BlackBox 

__One GDPR compliant fast stream encrpyter/decrypter.__

_(C) 2022 by Mariano Mancini_

A robust, fast, GDPR compliant, no-fix-key (autokey) encrypter with remote controllable decryption.
* GDPR data at rest     - yes, compliant
* GDPR data in transit  - yes, compliant
* GDPR data protection over 'data drop' to legal user remote machine - yes, compliant
 
## 

### Formato codifica file
***
 Z-block| Payload - blocco dati | Z-block
***
 ___Z-Block:___

Lo Z-Block è un piccolo blocco dati di __512 bytes__ che contiene una chiave locale crittografata utilizzata per codificare il payload del file.

Tale chiave di solito utilizza il nome originale del file _"paddato"_ a 16 o troncato a 32 bytes in modo da avere sempre chavi statisticamente diverse per ogni file.  
La chiave utilizzata per codificare lo _Z-Block_ dovrebbe essere __NON disponibile__ al sistema in cui gira lo script
e dovrebbe richiesta al sistema remoto ogni volta che si deve codificare/decodificare lo _Z-BLock_.

Per maggiore sicurezza lo _Z-Block_ è posto come blocco dati inizaile nel file crittografato finale,  e una copia identica
viene posta alla fine del file stesso in modo da poter recuperare  
le informazioni necessarie alla decodifica in caso di errata cancella zione del primo blocco.

Lo _Z-Block_ è composto in questo modo:

| Bytes          | Area    | Descrizione                                                        |
|:---------------|:--------|:-------------------------------------------------------------------| 
| ___26___       | Z-Block | Marcatura : "(C) 2022, Mariano Mancini "                           | 
| ___02___       | Z-Block | Lunghezza messaggio crittografato ( little endian )                
|                |         |
| ___08___       | Payload | Nonce crittografico CHACHA20                                       ||
| ___nn___       | Payload | Chiave locale crittografata CHACHA20 ( utilizzando chiave remota ) 
|                |         |
| ___16___       | Z-Block | Salt PBKDF2 ( chiave remota )                                                       
| ___03___       | Z-Block | Marcatura : "ORG"                                                  
| ___02___       | Z-Block | Lunghezza nome del file originale (little endian)                  
| ___nn___       | Z-Block | Nome originale del file                                            
| ___nn -> 512___ | Z-Block | Riempimento fino a 512 bytes                                       

___Payload/Blocco Dati:___  

Il blocco dati o Payload è un blocco crittografato utilizzando la chiave locale prelevata 
dallo __Z-Block__ il blocco è costituito in questo modo:

| Bytes    | Descrizione
|:---------| :-----
| ___08___ | Nonce crittografico ChaCha20
| ___nn___ | Dati crittografati
