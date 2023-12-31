#include "ast.h"
#include "hashmap.h"

#ifndef IR_H
#define IR_H

#define IR_SUCCESS (char)0
#define IR_FAIL (char)1
#define IR_WRONG_NODE (char)2
#define IR_ALREADY_INITIALIZED (char)3
#define IR_NOT_INITIALIZED (char)4

#define IR_TYPE_SIGNATURE_KIND_NIL (char)0
#define IR_TYPE_SIGNATURE_KIND_MAGIC (char)1
#define IR_TYPE_SIGNATURE_KIND_OBJECT (char)2
#define IR_TYPE_SIGNATURE_KIND_REF (char)3
#define IR_TYPE_SIGNATURE_KIND_PROC (char)4

#define IR_TYPE_MAGIC_REF_NIL (char)0
#define IR_TYPE_MAGIC_REF_NUMBER (char)1
#define IR_TYPE_MAGIC_REF_STRING (char)2

#define IR_SYMBOL_KIND_NIL (char)0
#define IR_SYMBOL_KIND_RTVAL (char)1
#define IR_SYMBOL_KIND_TYPEREF (char)2

#define CREATE_VAR_STRUCT_FUNCTION(STRUCT_NAME, TYPEORSYMBOL_NAME) struct STRUCT_NAME create_##TYPEORSYMBOL_NAME()
#define CREATE_VAR_STRUCT_FUNCTION_IMPL(STRUCT_NAME, KIND_ENUM) {\
    struct STRUCT_NAME out = {};\
    out.iKind = KIND_ENUM;\
    return out;\
}
#define NEW_VAR_STRUCT_FUNCTION(STRUCT_NAME, TYPEORSYMBOL_NAME) struct STRUCT_NAME* new_##TYPEORSYMBOL_NAME()
#define NEW_VAR_STRUCT_FUNCTION_IMPL(STRUCT_NAME, TYPEORSYMBOL_NAME) {\
    struct STRUCT_NAME* pout = (struct STRUCT_NAME*)malloc(sizeof(struct STRUCT_NAME));\
    if (pout != 0) *pout = create_##TYPEORSYMBOL_NAME();\
    return pout;\
}

struct ir_sig {
    char iKind;
};

struct ir_sig_magic {
    char iKind;
    char iCompilerMagic;
};

struct ir_sig_object {
    char iKind;
    struct vector vFields;
};

struct ir_sig_ref {
    char iKind;
    struct ir_typesig* tsRef;
};

struct ir_sig_proc {
    char iKind;
    struct vector vFormalParams;
    struct ir_typesig* tsRetType;
};

CREATE_VAR_STRUCT_FUNCTION(ir_sig_magic, sig_magic);
CREATE_VAR_STRUCT_FUNCTION(ir_sig_object, sig_object);
CREATE_VAR_STRUCT_FUNCTION(ir_sig_ref, sig_ref);
CREATE_VAR_STRUCT_FUNCTION(ir_sig_proc, sig_proc);
NEW_VAR_STRUCT_FUNCTION(ir_sig_magic, sig_magic);
NEW_VAR_STRUCT_FUNCTION(ir_sig_object, sig_object);
NEW_VAR_STRUCT_FUNCTION(ir_sig_ref, sig_ref);
NEW_VAR_STRUCT_FUNCTION(ir_sig_proc, sig_proc);

struct ir_sym {
    char iKind;
};

struct ir_sym_rtval {
    char iKind;
    struct type_signature* tsType;
};

struct ir_sym_typeref {
    char iKind;
    struct type_signature* tsRef;
};

struct scope_refs {
    struct scope_refs* srParent;
    struct hashmap hSymbols;
};

CREATE_VAR_STRUCT_FUNCTION(ir_sym_rtval, sym_rtval);
CREATE_VAR_STRUCT_FUNCTION(ir_sym_typeref, sym_typeref);
NEW_VAR_STRUCT_FUNCTION(ir_sym_rtval, sym_rtval);
NEW_VAR_STRUCT_FUNCTION(ir_sym_typeref, sym_typeref);

struct scope_refs create_scope_refs(struct scope_refs* srParent);
char scope_refs_assert_not_initialized(struct scope_refs* srSelf);
char init_scope_refs(struct scope_refs* srSelf);
char symbol_refs_unsafe_get_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_irSymbol);
char symbol_refs_unsafe_get_sibling_symbol_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_irSymbol);
char symbol_refs_add_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* irSymbol);
char deinit_scope_refs(struct scope_refs* srSelf);

char declare_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* irSymbol);
char generate_intermediate_repr_var_decl(struct scope_refs* srThisScope, struct ast_elem* aeVarDecl);
char generate_intermediate_hoisted_function_decl(struct scope_refs* srThisScope, struct ast_elem* aeRootElem);
char generate_intermediate_repr_stmt_list(struct scope_refs* srThisScope, struct ast_elem* aeRootElem);

#endif // IR_H  