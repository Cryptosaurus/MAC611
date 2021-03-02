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
@              optimised for speed
@
@ Comments:
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
@ theta No Round Const - LINEAR Step - MACRO
@ ------------------------------------------
@ DESCRIPTION
@   perform theta on state
@ INPUT:
@   r4-r7       = Half-theta key      (key is applied outside)
@   r0,r1,r2,r3 = a0,a1 ROL #1,a2,a3 ROL #2            !!!!!!!!!!!!!
@ OUTPUT:
@   r0,r1,r2,r9 = new state  !!!!!!!!!!!!!
@
@ Reserved reg. : R0,R12-R15
@ Modified reg. : $r0-$r3,$r8-$r9
@ Subproc Call  : Allowed
@------------------------------------------------------------------------------------------------
.macro thetaNC r0,r1,r2,r3,r4,r5,r6,r7,r8,r9
	eor \r0,\r4,\r0              @ add key ...
	eor \r1,\r5,\r1,ROR #1
	eor \r2,\r6,\r2
	eor \r9,\r7,\r3,ROR #2                           
	
	halftheta \r1,\r9,\r0,\r2,\r8,\r3
	
	halftheta \r0,\r2,\r1,\r9,\r8,\r3
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

@-------------------------------------------------------------------------------------------------
@ Entry code 
@-------------------------------------------------------------------------------------------------
	mov r12,r2	                @[sp]   =to text buffer pointer
	
	ldmia r1,{r0-r3}				@Read state from memory
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r0,r0
	rev r1,r1
	rev r2,r2
	rev r3,r3
#endif
	mov r1,r1,ROR #31				@ because theta take r1 = r1 ROR #31 as input  
	mov r9,r3,ROR #30             @                and r3 = r9 ROR #30  
@-------------------------------------------------------------------------------------------------


	fround 0x80,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x1B,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x36,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x6C,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	fround 0xD8,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0xAB,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x4D,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x9A,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	fround 0x2F,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x5E,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0xBC,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x63,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	fround 0xC6,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x97,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x35,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	fround 0x6A,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	eor r0,r0,#0xD4
	thetaNC r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r0,r0
	rev r1,r1
	rev r2,r2
	rev r3,r3
#endif
	stmia r12,{r0-r3}             @ Write back state in memory
	
	ldmia sp!,{r4-r12}
	mov pc,lr						@ return from subroutine
@================================================================================================


.macro iround RC,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9
	thetaNC \r0,\r1,\r2,\r3,\r4,\r5,\r6,\r7,\r8,\r9
	eor \r0,\r0,#\RC
	Pi1gammaPi2 \r0,\r1,\r2,\r9,\r8,\r3
.endm

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

@-------------------------------------------------------------------------------------------------
@ Entry code 
@-------------------------------------------------------------------------------------------------
	mov r12,r2         			@r12   =to text buffer pointer
	
	ldmia r1,{r0-r3}				@Read state from memory
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r0,r0
	rev r1,r1
	rev r2,r2
	rev r3,r3
#endif
	mov r1,r1,ROR #31				@ because theta take r1 = r1 ROR #31 as input  
	mov r9,r3,ROR #30             @                and r3 = r9 ROR #30  
@-------------------------------------------------------------------------------------------------

	iround 0xD4,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x6A,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x35,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x97,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	iround 0xC6,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x63,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0xBC,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x5E,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	iround 0x2F,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x9A,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x4D,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0xAB,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	iround 0xD8,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x6C,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x36,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	iround 0x1B,r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	
	thetaNC r0,r1,r2,r9,r4,r5,r6,r7,r8,r3
	eor r0,r0,#0x80
	
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rev r0,r0
	rev r1,r1
	rev r2,r2
	rev r3,r3
#endif
	stmia r12,{r0-r3}             @ Write back state in memory
	
	ldmia sp!,{r4-r12}
	mov pc,lr						@ return from subroutine
@================================================================================================
