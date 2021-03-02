@ Noekeon_ARM7.s
@
@ Last Modified: 00/08/30             Created: 00/08/30
@
@ Project    : Nessie Proposal: NOEKEON
@
@ Authors    : Joan Daemen, Michael Peeters, Vincent Rijmen, Gilles Van Assche
@
@ Written by : Michael Peeters
@
@ References : [NESSIE] see http://cryptonessie.org
@
@ Description: Optimised implementation on an ARM7 processor of NOEKEON in DIRECT KEY MODE
@              timing-attack resistant    
@              optimised for size
@
@ Comments:
@   Memory model is BIG ENDIAN: r0=0x12345678 
@                               --> Write in memory at 0x1000:  0x1000-78 56 34 12
@   PC=R15, LR=R14, SP=R13
@   Stack when interfacing with c: Decreasing before PUSH, Increasing after POP
@
@ Modified by XXXX for use with mbedOS on FRDM board (2019-01)
@ - removed NESSIE interface
@ - converted to GNU syntax
@ - save registers r4-r12
@ - use LITTLE ENDIAN: r0=0x12345678 
@                      --> Write in memory at 0x1000:  0x1000-78 56 34 12
@

	.syntax unified
	.text
	.align  4

.equ NROUND, 16				@ Number of Computation rounds in the block cipher

enccst:
	.byte 0x80, 0x1b, 0x36, 0x6c	@ Value of constant rounds
	.byte 0xd8, 0xab, 0x4d, 0x9a
	.byte 0x2f, 0x5e, 0xbc, 0x63
	.byte 0xc6, 0x97, 0x35, 0x6a
	.byte 0xd4, 0x00, 0x00, 0x00	@ last three constants added for alignment

deccst:
	.byte 0xd4, 0x6a, 0x35, 0x97	@ Value of constant rounds
	.byte 0xc6, 0x63, 0xbc, 0x5e
	.byte 0x2f, 0x9a, 0x4d, 0xab
	.byte 0xd8, 0x6c, 0x36, 0x1b
	.byte 0x80, 0x00, 0x00, 0x00	@ last three constants added for alignment

nulcst:
	.byte 0x00, 0x00, 0x00, 0x00	@ Value of constant rounds
	.byte 0x00, 0x00, 0x00, 0x00
	.byte 0x00, 0x00, 0x00, 0x00
	.byte 0x00, 0x00, 0x00, 0x00
	.byte 0x00, 0x00, 0x00, 0x00

@================================================================================================
@ halftheta - First and Third stage of the LINEAR - MACRO
@ -----------------------------------------------
@
@ $rout0 <- $rout0 + F($rin0,$rin1)
@ $rout1 <- $rout1 + F($rin0,$rin1)
@
@ Modified reg. : $rout0,$rout1,$r5,$r6
@================================================================================================
.macro halftheta rout0,rout1,rin0,rin1,r5,r6   
	eor \r6,\rin0,\rin1
	eor \r5,\r6,\r6,ROR #8
	eor \r5,\r5,\r6,ROR #24
	eor \rout0,\rout0,\r5
	eor \rout1,\rout1,\r5
.endm
@================================================================================================

@================================================================================================
@ (pi2)theta - (pi2)LINEAR Step - MACRO
@ -----------------------------
@ DESCRIPTION
@   perform theta on state, as well as round constant addition
@ INPUT:
@   r4-r7       = Half-theta key      (key is applied outside)
@   r0,r1,r2,r3 = a0,a1 ROL #1,a2,a3 ROL #2            !!!!!!!!!!!!!
@   r10         = first round constant
@   r11         = second round constant
@ OUTPUT:
@   r0,r1,r2,r9 = new state  !!!!!!!!!!!!!
@
@ Reserved reg. : R0,R12-R15
@ Modified reg. : $r0-$r3,$r8-$r9
@ Subproc Call  : Allowed
@------------------------------------------------------------------------------------------------
.macro theta r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12

	ldrb \r8,[\r10,\r12]		@ r10 = first round constant for this round
	eor \r0,\r0,\r8			@ add first round constant

	eor \r0,\r4,\r0			@ add key ...
	eor \r1,\r5,\r1,ROR #1
	eor \r2,\r6,\r2
	eor \r9,\r7,\r3,ROR #2                           

	halftheta \r1,\r9,\r0,\r2,\r8,\r3
  
	halftheta \r0,\r2,\r1,\r9,\r8,\r3

	ldrb \r8,[\r11,\r12]        	@ r10 = first round constant for this round
	eor \r0,\r0,\r8			@ add second round constant
  
.endm
@================================================================================================


@================================================================================================
@ Pi1gammaPi2 - Pi1, NONLINEAR Step, Pi2 - MACRO
@ ----------------------------------------------
@ DESCRIPTION
@   perform Pi2 o gamma o Pi1 on state
@ INPUT:
@   $r0,$r1,$r2,$r3 = state
@ OUTPUT:
@   $r0,$r1 ROR #31,$r2,$r5 ROR #30 = new state
@
@ Reserved reg. : R0,R12-R15
@ Modified reg. : $r0-$r5
@ Subproc Call  : Allowed
@
@ a reduced definition of gamma is  
@       r0 <- r0 ^ (r2 . r1)
@       r1 <- r1 ^ (r3 v r2)
@       r2 <- ~(r3 ^ r2 ^ r1 ^ r0)
@       r1 <- r1 ^ (r0 v r2)           
@       tmp<- r3 ^ (r2 . r1)
@       r3 <- r0                   SKIPPED
@       r0 <- tmp                  SKIPPED
@
@ rotations are merged in the computation of gamma & theta
@------------------------------------------------------------------------------------------------
.macro Pi1gammaPi2 r0,r1,r2,r3,r4,r5
@	mov \r1,\r1,ROR #31				@\r1 = a1 ROL #1     INCLUDED IN S-BOX
@	mov \r2,\r2,ROR #27				@\r2 = a2 ROL #5     INCLUDED IN S-BOX
@	mov \r3,\r3,ROR #30				@\r3 = a3 ROL #2     INCLUDED IN S-BOX

	and \r4,\r2,\r1,ROR #4
	eor \r5,\r0,\r4,ROR #27				@tmp <- r0 ^ (r2 . r1)
	orr \r4,\r2,\r3,ROR #3         
	eor \r1,\r4,\r1,ROR #4   			@r1 <- r1 ^ (r3 v r2)
	eor \r2,\r2,\r3,ROR #3
	eor \r2,\r2,\r1
	eor \r2,\r5,\r2,ROR #27
	mvn \r2,\r2,ROR #5				@r2 <- ~(r3 ^ r2 ^ r1 ^ tmp)
	orr \r4,\r5,\r2,ROR #27
	eor \r1,\r4,\r1,ROR #27           		@r1 <- r1 ^ (tmp v r2)
	and \r4,\r1,\r2,ROR #27  
	eor \r0,\r4,\r3,ROR #30           		@r0<- r3 ^ (r2 . r1)

@	mov \r1,\r1,ROR #1				@\r1 = a1 ROR #1    INCLUDED IN THETA - NEED PRE-LOOP ROR #31
@	mov \r2,\r2,ROR #5				@\r2 = a2 ROR #5    INCLUDED IN S-BOX
@	mov \r3,\r5,ROR #2				@\r3 = tmp ROR #2   INCLUDED IN THETA - NEED PRE-LOOP ROR #30

@ ==> current state is $r0,$r1 ROR #31,$r2,$r5 ROR #30
.endm
@================================================================================================

.macro fround RC,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9
	eor \r0,\r0,#\RC
	thetaNC \r0,\r1,\r2,\r3,\r4,\r5,\r6,\r7,\r8,\r9
	Pi1gammaPi2 \r0,\r1,\r2,\r9,\r8,\r3
.endm

@================================================================================================
@ NoekeonCore
@
@ DESCRIPTION:
@    perform the Noekeon Core
@ INPUT:
@   r4-r7 = half-theta key
@   r1 = from text buffer
@   r2 = to text buffer
@   r10 = Forward const ad
@   r11 = Backward const ad
@
@ OUTPUT:
@   cipher text written at r2
@
@ Reserved reg. : R12-R15
@ Modified reg. : none
@ Unmodif. reg. : all
@ Subproc Call  : Allowed
@------------------------------------------------------------------------------------------------
NoekeonCore:
@-------------------------------------------------------------------------------------------------
@ Entry code 
@-------------------------------------------------------------------------------------------------
	eor r12,r12,r12
	stmdb sp!,{r2}			@[sp]   =to text buffer pointer

	ldmia r1,{r0-r3}		@Read state from memory
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r0,r0
	rev r1,r1
	rev r2,r2
	rev r3,r3
#endif
	mov r1,r1,ROR #31		@ because theta take r1 = r1 ROR #31 as input  
	mov r9,r3,ROR #30		@                and r3 = r9 ROR #30  
@-------------------------------------------------------------------------------------------------
commonLoop:	@ Main Loop
					@ Pre: r12=round cntr, r0-r3=state, r4-r7=key
					@      r10 = fwdconst ad, r11 = bwdconst ad
@--- start of loop -------------------------------------------------------------------------------

	theta r0,r1,r2,r9,r4,r5,r6,r7,r8,r3,r10,r11,r12

	add r12,r12,#1			@ increment round counter
	cmp r12,#NROUND
	bhi endCommonLoop

	Pi1gammaPi2 r0,r1,r2,r3,r8,r9	@ do gamma
	b commonLoop

@--- end of loop ---------------------------------------------------------------------------------
endCommonLoop:

	ldr r12,[sp]			@ r12=to text buffer addr
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r0,r0
	rev r1,r1
	rev r2,r2
	rev r3,r3
#endif
	stmia r12,{r0-r3}		@ Write back state in memory

	ldmia sp!,{r2}			@ pop round counter
	ldmia sp!,{r4-r12}
	mov pc,lr			@ return from subroutine
@================================================================================================


@================================================================================================
@ void Noekeon_encrypt (const unsigned char * const key,
@                     const unsigned char * const plaintext,
@                     const unsigned char * const ciphertext)
@ DESCRIPTION:
@    encrypt the plaintext
@ INPUT:
@   r0 = const unsigned char * const key
@   r1 = const unsigned char * const plaintext
@   r2 = const unsigned char * const ciphertext
@ OUTPUT:
@   cipher text written at r2
@
@ Reserved reg. : R12-R15
@ Modified reg. : r0-r3
@------------------------------------------------------------------------------------------------

	.global Noekeon_encrypt
Noekeon_encrypt:
@-------------------------------------------------------------------------------------------------
@ Entry code 
@-------------------------------------------------------------------------------------------------
	stmdb sp!,{r4-r12}
	ldmia r0,{r4-r7}      		@load first key
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r4,r4
	rev r5,r5
	rev r6,r6
	rev r7,r7
#endif

	halftheta r5,r7,r4,r6,r8,r9

	ldr r10,=enccst
	ldr r11,=nulcst
  
	b NoekeonCore
@================================================================================================


@================================================================================================
@ void Noekeon_decrypt (const unsigned char * const key,
@                     const unsigned char * const ciphertext,
@                     const unsigned char * const plaintext)
@ DESCRIPTION:
@    decrypt the ciphertext
@ INPUT:
@   r0 = const unsigned char * const key
@   r1 = const unsigned char * const ciphertext
@   r2 = const unsigned char * const plaintext
@ OUTPUT:
@   plaintext text written at r2
@
@ Reserved reg. : R12-R15
@ Modified reg. : r0-r3
@------------------------------------------------------------------------------------------------

	.global Noekeon_decrypt
Noekeon_decrypt:
@-------------------------------------------------------------------------------------------------
@ Entry code 
@-------------------------------------------------------------------------------------------------
	stmdb sp!,{r4-r12}
	ldmia r0,{r4-r7}      		@load first key
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r4,r4
	rev r5,r5
	rev r6,r6
	rev r7,r7
#endif
	halftheta r4,r6,r5,r7,r8,r9

	ldr r10,=nulcst
	ldr r11,=deccst
  
	b NoekeonCore
@=================================================================================================
