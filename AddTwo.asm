;// file: AddTwo.asm
;// brief: RE project main file.
;// author: Aleksandra Skrbic(skrbicaleksandra@yahoo.com)
;//         Selena Colovic 
;// date: 30.05.2016.
;// last revision: 15.06.2016.
;// description: Dakle u okviru projektnog zadatka trebalo je dozvoliti da korisnik unese ime odgovarajuce playliste sa extenzijom .pls. Zatim se u okviru
;//              ovog koda provera validnost uzaznog fajla. Potom se vrsi obrada ulaznog fajla i sve se cuva u izlaznom fajlu sa extenzijom .m3u. Kada je
;//              obrada u pitanju, izlazni fajl ima odgovarajucu strukturu zahtevanu u tekstu samog projektnog zadatka.

;// Includes
INCLUDE Irvine32.inc
INCLUDE macros.inc

;// Declared data
BUFFER_SIZE = 50000

;// Data section- initialized data
.data
buffer BYTE BUFFER_SIZE DUP(?)                     ;// velicina prvog bafera za ucitavanje ULAZNOG fajla
buffer2 BYTE BUFFER_SIZE DUP(?)                    ;// velicina drugog bafera za smestanje obradjenog fajla i ispis u IZLAZNI fajl
srcFilename BYTE "initial_name.pls", 0             ;// ulazno ime fajla se smesta u ovaj string 
fileHandle   HANDLE ?                              ;// handle na izlazni file
startstring BYTE "#EXT3M3U", 0dh, 0ah              ;// string za pomoc u obradi tj. formiranju izlaznog fajla
extstring BYTE "#EXTINF:"                          ;// string za pomoc u obradi tj. formiranju izlaznog fajla

;// Code segment
.code
main PROC

;// Let user input a filename.
mWrite "Enter an input filename: "
mov	edx, OFFSET srcFilename
mov	ecx, SIZEOF srcFilename
call ReadString                                    ;// citamo u srcFilename string tj. ono sto je korisnik uneo kao ime ulaznog fajla .pls extenzija

;// Open the file for input.
sub edx, edx
mov	edx, OFFSET srcFilename
call OpenInputFile
mov	fileHandle, eax

;// Check for errors.
cmp	eax, INVALID_HANDLE_VALUE                      ;// error opening file ?
jne	file_ok                                        ;// no: skip
mWrite <"Cannot open file", 0dh, 0ah>
jmp	quit                                           ;// and quit

;// Read the file into a buffer.
file_ok:
mov	edx, OFFSET buffer
mov	ecx, BUFFER_SIZE
call ReadFromFile
jnc	check_buffer_size                              ;// error reading ?
mWrite "Error reading file. "                      ;// yes: show error message
call WriteWindowsMsg
jmp	close_file

check_buffer_size :
cmp	eax, BUFFER_SIZE                               ;// buffer large enough ?
jb	buf_size_ok                                    ;// yes
mWrite <"Error: Buffer too small for the file", 0dh, 0ah>
jmp	quit                                           ;// and quit

;// Display the buffer size.
buf_size_ok:
mov	buffer[eax], 0								   ;// insert null terminator
mWrite "File size: "
call WriteDec								       ;// display file size
call Crlf

;// Display the buffer.
mWrite <"Buffer:", 0dh, 0ah, 0dh, 0ah>
mov	edx, OFFSET buffer							   ;// display the buffer
call WriteString
call Crlf

close_file :
mov	eax, fileHandle
call CloseFile

cld                                                ;// CLEAR DIRECTION, brise flag smera => elementima stringa se pristupa u rastucem poretku
mov esi, OFFSET buffer                             ;// SOURCE INDEX REG. ukazuje na prvi element buffera (adresa prvog elementa u baferu) => ulaz
mov edi, OFFSET buffer2                            ;// DESTINATION INDEX REG. ukazuje na prvi element buffera2 (adresa prvog elementa u baferu2) => izlaz
mov bl, 1                                          ;// '1' => samo da znamo kada je prvi upis zbog pocetnog stringa za otput fajl (samo na pocetku fajla se javlja)

;// idem redom u ulaznom fajlu .pls sve dok ne dodjem do "=" , a onda ode u novi red => to je uloga petlji preskoci i preskoci_two
preskoci :
mov ecx, 100                                       ;// broj iteracija po svakoj instrukciji za rad sa stringovima; ide pointer dok ne nadje "="
mov al, "="
cmp [esi], al                                      ;// ako u baferu dodje do "=" to je onaj prvi red 
je preskoci_two
inc esi
jmp preskoci

preskoci_two :                                     ;// sad idemo od "=" u redu koji nam ne treba sve do pocetka sledeceg reda
mov al, 0dh
cmp [esi], al
je loop1pre
inc esi
jmp preskoci_two

;// ovo je nas red u kome se nalazi podatak o adresi
loop1pre :
add esi, 2                                        ;// sada samo pomerimo da pokazje na "F", to je red u kome je podatak koji nam treba!
loop1 :                                            
mov al, 0dh                                       ;// citaj do pocetka sledeceg reda
cmp [esi], al
je firstpush                                      ;// dodjemo do kraja stringa reda File_i tj. do pocetka Title_i 
inc esi
jmp loop1

;// upisivanje odg. dela File_i podatka na STEK 
firstpush :
mov eax, esi                                      ;// ACC ce nam pomoci da se obratimo clanovima u nizu koji obradjujemo (trentno 0dh), a u ESI pamtimo gde smo stali
add esi, 2                                        ;// ESI uvecamo da bi pokazivao na 'T' u Title_i redu to ce biti naredna obrada
firstpush_sub:                                   
mov cl, '='                                       ;// vracaj se unazad od kraja (0dh) sve dok ne detektujes "=" i to ce biti adresa
cmp [eax], cl
je loop2                                          ;// sada je podatak o adresi na steku
mov dl, [eax]
mov [esp], dl                                     ;// stek raste ka nizim mem. lokacijama, ukazje na poslednju zauzetu
dec esp                                           ;// stek pointer pomeramo po svakom upisu na odg. nacin
dec eax                                           ;// idemo nazad u stringu koji obradjujemo sve dok ne ocita "="
jmp firstpush_sub

loop2 :
mov al, 0dh                                       ;// idemo sada od 'T' (tu smo stali) tj. citamo sad do kraja Title_i reda za ime
cmp [esi], al
je secondpush
inc esi
jmp loop2

;// upisivanje imena => Title_i na stek
secondpush :
mov eax, esi                                      ;// ACC ce nam pomoci da se obratimo clanovima u nizu koji obradjujemo (trentno 0dh), a u ESI pamtimo gde smo stali
add esi, 2                                        ;// ESI uvecamo da bi pokazivao na 'L' u Length_i redu to ce biti naredna obrada
mov cl, '='                                       ;// idi unazad sve dok ne ocitas "=", tada ces imati celo ime
secondpush_sub :
cmp [eax], cl                                     ;// vracaj se unazad od kraja (0dh) sve dok ne detektujes "=" i to ce biti ime
je loop3
mov dl, [eax]
mov [esp], dl
dec esp                                           ;// stek pointer pomeramo po svakom upisu na odg. nacin
dec eax                                           ;// idemo nazad u stringu koji obradjujemo sve dok ne ocita "="
jmp secondpush_sub

loop3 :
mov al, 0dh                                       ;// idemo po sad  kraja reda Length_i za vreme tj. MOZDA i do kraja fajla!
cmp[esi], al
je thirdpush
mov al, 0h                                        ;// ovo je za slucaj kada ce to biti kraj fajla
cmp [esi], al
je thirdpush
inc esi
jmp loop3

;// upisivanje vremena trajanja numere => Length_i na STEK
thirdpush :
mov eax, esi                                      ;// ACC ce nam pomoci da se obratimo clanovima u nizu koji obradjujemo (trentno 0dh), a u ESI pamtimo gde smo stali
add esi, 2                                        ;// ESI uvecamo da bi pokazivao na 'F' u File_j redu (to je novi segment tj. numera) to ce biti naredna obrada
thirdpush_sub :                                  
mov cl, '='                                       ;// vracaj se unazad od kraja dok ne detektujes "=" i to ce biti vreme
cmp[eax], cl
je upis_buffer2                                   ;// nakon svakog obradjenog segmenta File-Title-Length upisuj to u izlazni bafer
mov cl, 0h                                        ;// za slucaj da dodje do kraja fajla, tj. da je ovo poslednja obrada idi na obradu kraj_fajla
cmp [eax], cl
je kraj_fajla
mov dl, [eax]
mov [esp], dl
dec esp                                           ;// stek pointer pomeramo po svakom upisu na odg. nacin
dec eax                                           ;// idemo nazad u stringu koji obradjujemo sve dok ne ocita "="
jmp thirdpush_sub

kraj_fajla:
dec eax                                           ;// za slucaj da je EOF vrati se samo nazad za jedan karakter to ne stavljamo na STEK
dec esi                                           ;// za slucaj da je EOF vrati se samo nazad za jedan karakter 
jmp thirdpush_sub

;// upis u bafer2
upis_buffer2 :
mov eax, esi
cmp bl, 1                                         ;// ako je prvi upis stavi kljucnu rec na pocetak izlaznog fajla => sartstring
jne upis
mov esi, OFFSET startstring                       ;// samo za prvu iteraciju, ispis pocetne kljucne reci, zato nam je trebao ovaj brojac u LOW BASE REG. => BL
mov ecx, LENGTHOF startstring
rep movsb

upis :
mov esi, OFFSET extstring                         ;// ispis pocetka reda u kome su Length_i i Title_i
mov ecx, LENGTHOF extstring
rep movsb

upis_LENGTH:
inc esp                                           ;// pomerimo stek pointer (trenutno na 0dh), da pokazuje na pocetni karakter koji je vrednost vremena trajanja
mov dl, [esp]
mov [edi], dl                                     ;// iz SP koji ukazuje na podatak na steku prebacjemo vrednost sa steka u EDI koji ukazuje na podatak u buffer2, tj. prebacujemo odg. niz podataka u izlazni bafer
inc edi                                           ;// inkrementiramo adresu podatka u izlaznom baferu za upis novog podatka
cmp dl, 0dh                                       
jne upis_LENGTH                                   ;// kraj zeljenog formata stringa (upis na steku se zavrsavao sa 0dh), vreme je sada upisano u izlazni bafer
dec edi                                           ;// skini ono 0dh jer cemo u istom redu upisivati i Title_i
mov dl, ","                                       ;// kad upisesemo vreme stavimo "," jer je takav trazeni format .m3u fajla
mov [edi], dl
inc edi                                           ;// inkrementiramo adresu podatka u izlaznom baferu za upis novog podatka

upis_TITLE :
inc esp                                           ;// pomerimo stek pointer (trenutno na 0dh), da pokazuje na pocetni karakter koji je vrednost imena numere
mov dl, [esp]
mov [edi], dl                                     ;// iz SP koji ukazuje na podatak na steku prebacjemo vrednost sa steka u EDI koji ukazuje na podatak u buffer2, tj. prebacujemo odg. niz podataka u izlazni bafer
inc edi                                           ;// inkrementiramo adresu podatka u izlaznom baferu za upis novog podatka
cmp dl, 0dh                                       ;// kraj zeljenog formata stringa (upis na steku se zavrsavao sa 0dh), ime numere je sada upisano u izlazni bafer
jne upis_TITLE

upis_FILE :
inc esp                                           ;// pomerimo stek pointer (trenutno na 0dh),da pokazuje na pocetni karakter koji je vrednost adrese (putanje) numere
mov dl, [esp]
mov [edi], dl                                     ;// iz SP koji ukazuje na podatak na steku prebacjemo vrednost sa steka u EDI koji ukazuje na podatak u buffer2, tj. prebacujemo odg. niz podataka u izlazni bafer
inc edi                                           ;// inkrementiramo adresu podatka u izlaznom baferu za upis novog podatka
cmp dl, 0dh                                       ;// kraj zeljenog formata stringa (upis na steku se zavrsavao sa 0dh), putanja do numere je sada upisana u izlazni bafer
jne upis_FILE
inc bl                                            ;// kada zavrsimo prvi upis inkrementiramo brojac da ne bi stalno ispisivao START string u outpt file-u
mov esi, eax                     
mov cl, 0h
cmp [esi], cl                                     ;// kada doodje do EOF izadji jer je upis zavrsen, u protivnom se vrtimo u petlji sve dok ne obradimo sve pakete podataka iz ulaznog fajla
jne loop1

;// ovaj deo se odnosi na formiranje imena izlaznog fajla, na osnovu srcFilename koje korisnik unosi
cld                                               ;// CLEAR DIRECTION, brise flag smera => elementima stringa se pristupa u rastucem poretku
mov ecx, 1                                        ;// broj iteracija po svakoj instrukciji za rad sa stringovima
sub edi, edi                                      ;// DESTINATION INDEX REGISTER = 0, ima ulogu pokazivaca tj. tu je adresa pocetnog elementa stringa
mov edi, OFFSET srcFilename                       ;// prosledimo mu offset adrese na string srcFilename, sad ukazuje na njegov pocetak

;// sad formiramo deo koji nam treba od ulaznog imena
izlaz_ime :
mov al, "."                                       ;// u donji bajt akumulatora ubacimo string "."
cmp [edi], al                                     ;// poredimo trenutni element u stringu sa "." 
je extenzija                                      ;// kada stigne do tacke u ulaznom imenu tu stajemo => to nam treba, sad ostaje samo da promenimo extenziju
inc edi                                           ;// ukoliko jos nije stigao do tacke inkrementiraj pointer
jmp izlaz_ime                                     ;// vrati se da proveris novi element

;// ovaj deo sada sluzi da dodamo odgovarajucu extenziju za formiranje imena izlaznog fajla
extenzija :
inc edi                                           ;// posto edi u tom trenutku ukazuje na "."
mov dl, "m"                                       ;// u donji bajt DATA REGISTER-a stavimo string "m" od extenzije M3U
mov [edi], dl                                     ;// posle tacke u do sada obradjenom stringu najpre dodamo "m"
inc edi                                           ;// dodajemo dalje
mov dl, "3"                                       ;// u donji bajt DATA REGISTER-a stavimo string "3" od extenzije M3U
mov [edi], dl                                     ;// posle "m" u do sada obradjenom stringu dodamo "3"
inc edi                                           ;// dodajemo dalje
mov dl, "u"                                       ;// u donji bajt DATA REGISTER-a stavimo string "u" od extenzije M3U
mov [edi], dl                                     ;// posle "3" u do sada obradjenom stringu dodamo za kraj "u"

;// Create a new text file.
sub edx, edx                                      ;// clear DATA REGISTER
mov	edx, OFFSET srcFilename                       ;// u DATA REG. je adresa pocetnog elementa stringa
call CreateOutputFile                             ;// kreiramo fajl sa nazivom koji je zapravo modifikovani string srcFileName
mov	fileHandle, eax                               ;// handle na fajl koji smo kreirali cuvamo u odg. promenljivoj

;// Write the buffer to the output file.
mov	eax, fileHandle                               ;// handle na output file u koji upisujemo, smestimo u ACC
mov	edx, OFFSET buffer2                           ;// u Data reg. ubacimo adresu pocetnog elemenata iz bafera
mov	ecx, LENGTHOF buffer2                         ;// u counter ubacimo koliko elemenata ima ovaj bafer
sub ecx, 43039                                    ;// ovaj red je napisan da ne bi bilo NULL karaktera u izlaznom fajlu. zakomentarisati !!! ukoliko se koristi neki primer drugaciji od playlista datih u okviru projekta
call WriteToFile                                  ;// ispisujemo elemente sve dok counter ne dodje do 0, i to u izlazni fajl koji smo kreirali

;// Display the return value.
quit :
exit

main ENDP
END main