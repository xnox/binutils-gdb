/* BFD back-end for ARM v6 (aka AArch64) COFF files.
   Copyright (C) 2006-2017 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.

   Written by Kai Tietz, OneVision Software GmbH&CoKg.  */

#ifndef COFF_WITH_peaa64
#define COFF_WITH_peaa64
#endif

#define AA64

/* Note we have to make sure not to include headers twice.
   Not all headers are wrapped in #ifdef guards, so we define
   PEI_HEADERS to prevent double including here.  */
#ifndef PEI_HEADERS
#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "coff/aa64.h"
#include "coff/internal.h"
#include "coff/pe.h"
#include "libcoff.h"
#include "libiberty.h"
#endif

#define BADMAG(x) AA64BADMAG(x)

#ifdef COFF_WITH_peaa64
# undef  AOUTSZ
# define AOUTSZ		PEPAOUTSZ
# define PEAOUTHDR	PEPAOUTHDR
#endif

#define COFF_DEFAULT_SECTION_ALIGNMENT_POWER (2)

/* The page size is a guess based on ELF.  */

#define COFF_PAGE_SIZE 0x1000

/* For some reason when using AMD COFF the value stored in the .text
   section for a reference to a common symbol is the value itself plus
   any desired offset.  Ian Taylor, Cygnus Support.  */

/* If we are producing relocatable output, we need to do some
   adjustments to the object file that are not done by the
   bfd_perform_relocation function.  This function is called by every
   reloc type to make any required adjustments.  */

static bfd_reloc_status_type
coff_arm64_reloc (bfd *abfd,
		  arelent *reloc_entry,
		  asymbol *symbol,
		  void * data,
		  asection *input_section ATTRIBUTE_UNUSED,
		  bfd *output_bfd,
		  char **error_message ATTRIBUTE_UNUSED)
{
  symvalue diff;

  if (bfd_is_com_section (symbol->section))
    {
      /* In PE mode, we do not offset the common symbol.  */
      diff = reloc_entry->addend;
    }
  else
    {
      /* For some reason bfd_perform_relocation always effectively
	 ignores the addend for a COFF target when producing
	 relocatable output.  This seems to be always wrong for 386
	 COFF, so we handle the addend here instead.  */
      if (output_bfd == NULL)
	{
	  reloc_howto_type *howto = reloc_entry->howto;

	  /* Although PC relative relocations are very similar between
	     PE and non-PE formats, but they are off by 1 << howto->size
	     bytes. For the external relocation, PE is very different
	     from others. See md_apply_fix3 () in gas/config/tc-amd64.c.
	     When we link PE and non-PE object files together to
	     generate a non-PE executable, we have to compensate it
	     here.  */
	  if(howto->pc_relative && howto->pcrel_offset)
	    diff = -(1 << howto->size);
	  else if(symbol->flags & BSF_WEAK)
	    diff = reloc_entry->addend - symbol->value;
	  else
	    diff = -reloc_entry->addend;
	}
      else
	diff = reloc_entry->addend;
    }

# if defined(COFF_WITH_PE)
  /* FIXME: How should this case be handled?  */
  if (reloc_entry->howto->type == IMAGE_REL_ARM64_ADDR32NB
      && output_bfd != NULL
      && bfd_get_flavour (output_bfd) == bfd_target_coff_flavour)
    diff -= pe_data (output_bfd)->pe_opthdr.ImageBase;
#endif

#define DOIT(x) \
  x = ((x & ~howto->dst_mask) | (((x & howto->src_mask) + diff) & howto->dst_mask))

  if (diff != 0)
    {
      reloc_howto_type *howto = reloc_entry->howto;
      unsigned char *addr = (unsigned char *) data + reloc_entry->address;

      /* FIXME: We do not have an end address for data, so we cannot
	 accurately range check any addresses computed against it.
	 cf: PR binutils/17512: file: 1085-1761-0.004.
	 For now we do the best that we can.  */
      if (addr < (unsigned char *) data
	  || addr > ((unsigned char *) data) + input_section->size)
	{
	  bfd_set_error (bfd_error_bad_value);
	  return bfd_reloc_notsupported;
	}

      switch (howto->size)
	{
	case 0:
	  {
	    char x = bfd_get_8 (abfd, addr);
	    DOIT (x);
	    bfd_put_8 (abfd, x, addr);
	  }
	  break;

	case 1:
	  {
	    short x = bfd_get_16 (abfd, addr);
	    DOIT (x);
	    bfd_put_16 (abfd, (bfd_vma) x, addr);
	  }
	  break;

	case 2:
	  {
	    long x = bfd_get_32 (abfd, addr);
	    DOIT (x);
	    bfd_put_32 (abfd, (bfd_vma) x, addr);
	  }
	  break;

	case 4:
	  {
	    bfd_uint64_t x = bfd_get_64 (abfd, addr);
	    DOIT (x);
	    bfd_put_64 (abfd, x, addr);
	  }
	  break;

	default:
	  bfd_set_error (bfd_error_bad_value);
	  return bfd_reloc_notsupported;
	}
    }

  /* Now let bfd_perform_relocation finish everything up.  */
  return bfd_reloc_continue;
}

/* Return TRUE if this relocation should appear in the output .reloc
   section.  */

static bfd_boolean
in_reloc_p (bfd *abfd ATTRIBUTE_UNUSED, reloc_howto_type *howto)
{
  return ! howto->pc_relative && howto->type != IMAGE_REL_ARM64_ADDR32NB
	 && howto->type != BFD_RELOC_32_SECREL;
}

#ifndef PCRELOFFSET
#define PCRELOFFSET TRUE
#endif

static reloc_howto_type howto_table[] =
{
  EMPTY_HOWTO (0),
  HOWTO (IMAGE_REL_ARM64_ADDR32,/* type 1 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_ADDR32",		/* name */
	 TRUE,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_ADDR32NB,/* type 2 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_ADDR32NB",	/* name */
	 TRUE,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_BRANCH26,/* type 3 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 26,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_BRANCH26",	/* name */
	 TRUE,			/* partial_inplace */
	 0x03ffffff,		/* src_mask */
	 0x03ffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_PAGEBASE_REL21,/* type 4 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 21,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_PAGEBASE_REL21",	/* name */
	 TRUE,			/* partial_inplace */
	 0xfffff800,		/* src_mask */
	 0xfffff800,		/* dst_mask */
	 PCRELOFFSET),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_REL21, /* type 5 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 21,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_REL21",/* name */
	 FALSE,			/* partial_inplace */
	 0x001fffff,		/* src_mask */
	 0x001fffff,		/* dst_mask */
	 PCRELOFFSET),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_PAGEOFFSET_12A,/* type 6 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 12,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_PAGEOFFSET_12A",/* name */
	 FALSE,			/* partial_inplace */
	 0x00000fff,		/* src_mask */
	 0x00000fff,		/* dst_mask */
	 PCRELOFFSET),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_PAGEOFFSE_12L,/* type 7 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 12,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_PAGEOFFSE_12L",/* name */
	 FALSE,			/* partial_inplace */
	 0x00000fff,		/* src_mask */
	 0x00000fff,		/* dst_mask */
	 PCRELOFFSET),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_SECREL,/* type 8 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_SECREL",	/* name */
	 TRUE,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_SECREL_LO12A,/* type 9 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 12,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_SECREL_LO12A",/* name */
	 TRUE,			/* partial_inplace */
	 0x00000fff,		/* src_mask */
	 0x00000fff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_SECREL_HI12A,/* type 10 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 12,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_SECREL_HI12A",/* name */
	 TRUE,			/* partial_inplace */
	 0x00fff000,		/* src_mask */
	 0x00fff000,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
  HOWTO (IMAGE_REL_ARM64_SECREL_LO12L,/* type 11 */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 12,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_SECREL_LO12L",/* name */
	 TRUE,			/* partial_inplace */
	 0x00000fff,		/* src_mask */
	 0x00000fff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
  EMPTY_HOWTO (IMAGE_REL_ARM64_TOKEN),/* type 12 */
  EMPTY_HOWTO (IMAGE_REL_ARM64_SECTION),/* type 13 */
  HOWTO (IMAGE_REL_ARM64_ADDR64,/* type 14 */
	 0,			/* rightshift */
	 4,			/* size (0 = byte, 1 = short, 2 = long, 4 = long long) */
	 64,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 coff_arm64_reloc,	/* special_function */
	 "IMAGE_REL_ARM64_ADDR64",	/* name */
	 TRUE,			/* partial_inplace */
	 0xffffffffffffffffll,	/* src_mask */
	 0xffffffffffffffffll,	/* dst_mask */
	 PCRELOFFSET),		/* pcrel_offset */
};

#define NUM_HOWTOS ARRAY_SIZE (howto_table)

/* Turn a howto into a reloc  nunmber */

#define SELECT_RELOC(x,howto) { x.r_type = howto->type; }
#define ARM64 1

#define RTYPE2HOWTO(cache_ptr, dst)		\
  ((cache_ptr)->howto =				\
   ((dst)->r_type < NUM_HOWTOS)			\
    ? howto_table + (dst)->r_type		\
    : NULL)

/* For 386 COFF a STYP_NOLOAD | STYP_BSS section is part of a shared
   library.  On some other COFF targets STYP_BSS is normally
   STYP_NOLOAD.  */
#define BSS_NOLOAD_IS_SHARED_LIBRARY

/* Compute the addend of a reloc.  If the reloc is to a common symbol,
   the object file contains the value of the common symbol.  By the
   time this is called, the linker may be using a different symbol
   from a different object file with a different value.  Therefore, we
   hack wildly to locate the original symbol from this file so that we
   can make the correct adjustment.  This macro sets coffsym to the
   symbol from the original file, and uses it to set the addend value
   correctly.  If this is not a common symbol, the usual addend
   calculation is done, except that an additional tweak is needed for
   PC relative relocs.
   FIXME: This macro refers to symbols and asect; these are from the
   calling function, not the macro arguments.  */

#define CALC_ADDEND(abfd, ptr, reloc, cache_ptr)		\
  {								\
    coff_symbol_type *coffsym = NULL;				\
								\
    if (ptr && bfd_asymbol_bfd (ptr) != abfd)			\
      coffsym = (obj_symbols (abfd)				\
	         + (cache_ptr->sym_ptr_ptr - symbols));		\
    else if (ptr)						\
      coffsym = coff_symbol_from (ptr);				\
								\
    if (coffsym != NULL						\
	&& coffsym->native->u.syment.n_scnum == 0)		\
      cache_ptr->addend = - coffsym->native->u.syment.n_value;	\
    else if (ptr && bfd_asymbol_bfd (ptr) == abfd		\
	     && ptr->section != NULL)				\
      cache_ptr->addend = - (ptr->section->vma + ptr->value);	\
    else							\
      cache_ptr->addend = 0;					\
    if (ptr && reloc.r_type < NUM_HOWTOS			\
	&& howto_table[reloc.r_type].pc_relative)		\
      cache_ptr->addend += asect->vma;				\
  }

/* The PE relocate section routine.  The only difference between this
   and the regular routine is that we don't want to do anything for a
   relocatable link.  */

static bfd_boolean
coff_pe_arm64_relocate_section (bfd *output_bfd,
				struct bfd_link_info *info,
				bfd *input_bfd,
				asection *input_section,
				bfd_byte *contents,
				struct internal_reloc *relocs,
				struct internal_syment *syms,
				asection **sections)
{
  if (bfd_link_relocatable (info))
    return TRUE;

  return _bfd_coff_generic_relocate_section (output_bfd, info, input_bfd,input_section, contents,relocs, syms, sections);
}

#define coff_relocate_section coff_pe_arm64_relocate_section

/* Convert an rtype to howto for the COFF backend linker.  */

static reloc_howto_type *
coff_arm64_rtype_to_howto (bfd *abfd ATTRIBUTE_UNUSED,
			   asection *sec,
			   struct internal_reloc *rel,
			   struct coff_link_hash_entry *h,
			   struct internal_syment *sym,
			   bfd_vma *addendp)
{
  reloc_howto_type *howto;

  if (rel->r_type >= NUM_HOWTOS)
    {
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }
  howto = howto_table + rel->r_type;

  /* Cancel out code in _bfd_coff_generic_relocate_section.  */
  *addendp = 0;

  if (howto->pc_relative)
    *addendp += sec->vma;

  if (sym != NULL && sym->n_scnum == 0 && sym->n_value != 0)
    {
      /* This is a common symbol.  The section contents include the
	 size (sym->n_value) as an addend.  The relocate_section
	 function will be adding in the final value of the symbol.  We
	 need to subtract out the current size in order to get the
	 correct result.  */
      BFD_ASSERT (h != NULL);

    }

  if (howto->pc_relative)
    {
	*addendp -= 4;

      /* If the symbol is defined, then the generic code is going to
         add back the symbol value in order to cancel out an
         adjustment it made to the addend.  However, we set the addend
         to 0 at the start of this function.  We need to adjust here,
         to avoid the adjustment the generic code will make.  FIXME:
         This is getting a bit hackish.  */
      if (sym != NULL && sym->n_scnum != 0)
	*addendp -= sym->n_value;
    }

  if (rel->r_type == IMAGE_REL_ARM64_ADDR32NB
      && (bfd_get_flavour (sec->output_section->owner) == bfd_target_coff_flavour))
    *addendp -= pe_data (sec->output_section->owner)->pe_opthdr.ImageBase;

  if (rel->r_type == BFD_RELOC_32_SECREL)
    {
      bfd_vma osect_vma;

      if (h && (h->root.type == bfd_link_hash_defined
		|| h->root.type == bfd_link_hash_defweak))
	osect_vma = h->root.u.def.section->output_section->vma;
      else
	{
	  asection *s;
	  int i;

	  /* Sigh, the only way to get the section to offset against
	     is to find it the hard way.  */
	  for (s = abfd->sections, i = 1; i < sym->n_scnum; i++)
	    s = s->next;

	  osect_vma = s->output_section->vma;
	}

      *addendp -= osect_vma;
    }

  return howto;
}

#define coff_bfd_reloc_type_lookup coff_arm64_reloc_type_lookup
#define coff_bfd_reloc_name_lookup coff_arm64_reloc_name_lookup

static reloc_howto_type *
coff_arm64_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code)
{
#define ASTD(i,j)       case i: return howto_table + j
  switch (code)
    {
      ASTD (BFD_RELOC_AARCH64_NONE,		IMAGE_REL_ARM64_ABSOLUTE);
      ASTD (BFD_RELOC_32,			IMAGE_REL_ARM64_ADDR32);
      ASTD (BFD_RELOC_RVA,			IMAGE_REL_ARM64_ADDR32NB);
      ASTD (BFD_RELOC_AARCH64_JUMP26,		IMAGE_REL_ARM64_BRANCH26);
      ASTD (BFD_RELOC_AARCH64_ADR_HI21_PCREL,	IMAGE_REL_ARM64_PAGEBASE_REL21);
      ASTD (BFD_RELOC_AARCH64_ADR_LO21_PCREL,	IMAGE_REL_ARM64_REL21);
      ASTD (BFD_RELOC_AARCH64_ADD_LO12,		IMAGE_REL_ARM64_PAGEOFFSET_12A);
      ASTD (BFD_RELOC_AARCH64_LDST8_LO12,	IMAGE_REL_ARM64_PAGEOFFSE_12L);
      ASTD (BFD_RELOC_32_SECREL,		IMAGE_REL_ARM64_SECREL);
      ASTD (BFD_RELOC_AARCH64_ADD_LO12_SECREL,	IMAGE_REL_ARM64_SECREL_LO12A);
      ASTD (BFD_RELOC_AARCH64_ADD_HI12_SECREL,	IMAGE_REL_ARM64_SECREL_HI12A);
      ASTD (BFD_RELOC_AARCH64_LDST8_LO12_SECREL,IMAGE_REL_ARM64_SECREL_LO12L);
      ASTD (BFD_RELOC_SECTION,			IMAGE_REL_ARM64_SECTION);
      ASTD (BFD_RELOC_64,			IMAGE_REL_ARM64_ADDR64);
      ASTD (BFD_RELOC_AARCH64_BRANCH19,		IMAGE_REL_ARM64_BRANCH19);
      ASTD (BFD_RELOC_AARCH64_TSTBR14,		IMAGE_REL_ARM64_BRANCH14);
      ASTD (BFD_RELOC_32_PCREL,			IMAGE_REL_ARM64_REL32);
    default:
      BFD_FAIL ();
      return 0;
    }
}

static reloc_howto_type *
coff_arm64_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			      const char *r_name)
{
  unsigned int i;

  for (i = 0; i < NUM_HOWTOS; i++)
    if (howto_table[i].name != NULL
	&& strcasecmp (howto_table[i].name, r_name) == 0)
      return &howto_table[i];

  return NULL;
}

#define coff_rtype_to_howto coff_arm64_rtype_to_howto

#ifdef TARGET_UNDERSCORE

/* If aarch64 gcc uses underscores for symbol names, then it does not use
   a leading dot for local labels, so if TARGET_UNDERSCORE is defined we treat
   all symbols starting with L as local.  */

static bfd_boolean
coff_arm64_is_local_label_name (bfd *abfd, const char *name)
{
  if (name[0] == 'L')
    return TRUE;

  return _bfd_coff_is_local_label_name (abfd, name);
}

#define coff_bfd_is_local_label_name coff_arm64_is_local_label_name

#endif /* TARGET_UNDERSCORE */

#ifndef bfd_pe_print_pdata
#define bfd_pe_print_pdata   NULL
#endif

#include "coffcode.h"

#ifdef PE
#define aa64coff_object_p pe_bfd_object_p
#else
#define aa64coff_object_p coff_object_p
#endif

const bfd_target
#ifdef TARGET_SYM
  TARGET_SYM =
#else
# error TARGET_SYM is not defined
#endif
{
#ifdef TARGET_NAME
  TARGET_NAME,
#else
# error TARGET_NAME is not defined
#endif
  bfd_target_coff_flavour,
  BFD_ENDIAN_LITTLE,		/* Data byte order is little.  */
  BFD_ENDIAN_LITTLE,		/* Header byte order is little.  */

  (HAS_RELOC | EXEC_P |		/* Object flags.  */
   HAS_LINENO | HAS_DEBUG |
   HAS_SYMS | HAS_LOCALS | WP_TEXT | D_PAGED | BFD_COMPRESS | BFD_DECOMPRESS),

  (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_RELOC /* Section flags.  */
   | SEC_LINK_ONCE | SEC_LINK_DUPLICATES | SEC_READONLY | SEC_DEBUGGING
   | SEC_CODE | SEC_DATA | SEC_EXCLUDE ),

#ifdef TARGET_UNDERSCORE
  TARGET_UNDERSCORE,		/* Leading underscore.  */
#else
  0,				/* Leading underscore.  */
#endif
  '/',				/* Ar_pad_char.  */
  15,				/* Ar_max_namelen.  */
  0,				/* match priority.  */
  TARGET_KEEP_UNUSED_SECTION_SYMBOLS, /* keep unused section symbols.  */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
     bfd_getl32, bfd_getl_signed_32, bfd_putl32,
     bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* Data.  */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
     bfd_getl32, bfd_getl_signed_32, bfd_putl32,
     bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* Hdrs.  */

  /* Note that we allow an object file to be treated as a core file as well.  */
  {				/* BFD_check_format.  */
    _bfd_dummy_target,
    aa64coff_object_p,
    bfd_generic_archive_p,
    aa64coff_object_p
  },
  {				/* bfd_set_format.  */
    _bfd_bool_bfd_false_error,
    coff_mkobject,
    _bfd_generic_mkarchive,
    _bfd_bool_bfd_false_error
  },
  {				/* bfd_write_contents.  */
    _bfd_bool_bfd_false_error,
    coff_write_object_contents,
    _bfd_write_archive_contents,
    _bfd_bool_bfd_false_error
  },

  BFD_JUMP_TABLE_GENERIC (coff),
  BFD_JUMP_TABLE_COPY (coff),
  BFD_JUMP_TABLE_CORE (_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE (_bfd_archive_coff),
  BFD_JUMP_TABLE_SYMBOLS (coff),
  BFD_JUMP_TABLE_RELOCS (coff),
  BFD_JUMP_TABLE_WRITE (coff),
  BFD_JUMP_TABLE_LINK (coff),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,

  COFF_SWAP_TABLE
};
