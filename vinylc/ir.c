#include "ir.h"
#include <stdlib.h>

CREATE_VAR_STRUCT_FUNCTION(ir_sig_magic, sig_magic) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_sig_magic, IR_TYPE_SIGNATURE_KIND_MAGIC);
CREATE_VAR_STRUCT_FUNCTION(ir_sig_object, sig_object) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_sig_object, IR_TYPE_SIGNATURE_KIND_OBJECT);
CREATE_VAR_STRUCT_FUNCTION(ir_sig_ref, sig_ref) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_sig_ref, IR_TYPE_SIGNATURE_KIND_REF);
CREATE_VAR_STRUCT_FUNCTION(ir_sig_proc, sig_proc) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_sig_proc, IR_TYPE_SIGNATURE_KIND_PROC);
NEW_VAR_STRUCT_FUNCTION(ir_sig_magic, sig_magic) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_sig_magic, sig_magic);
NEW_VAR_STRUCT_FUNCTION(ir_sig_object, sig_object) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_sig_object, sig_object);
NEW_VAR_STRUCT_FUNCTION(ir_sig_ref, sig_ref) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_sig_ref, sig_ref);
NEW_VAR_STRUCT_FUNCTION(ir_sig_proc, sig_proc) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_sig_proc, sig_proc);

CREATE_VAR_STRUCT_FUNCTION(ir_sym_rtval, sym_rtval) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_sym_rtval, IR_SYMBOL_KIND_RTVAL);
CREATE_VAR_STRUCT_FUNCTION(ir_sym_typeref, sym_typeref) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_sym_typeref, IR_SYMBOL_KIND_TYPEREF);
NEW_VAR_STRUCT_FUNCTION(ir_sym_rtval, sym_rtval) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_sym_rtval, sym_rtval);
NEW_VAR_STRUCT_FUNCTION(ir_sym_typeref, sym_typeref) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_sym_typeref, sym_typeref);

struct scope_refs create_scope_refs(struct scope_refs* srParent) {
    struct scope_refs out = {};
    out.hSymbols = create_hashmap(127, fnv1a_key_hash_str, key_compare_strcmp);
    out.srParent = srParent;
    return out;
}

char scope_refs_assert_not_initialized(struct scope_refs* srSelf) {
    return hashmap_assert_not_initialized(&srSelf->hSymbols) == HASHMAP_FAIL ? IR_FAIL : IR_SUCCESS;
}

char init_scope_refs(struct scope_refs* srSelf) {
    if (scope_refs_assert_not_initialized(srSelf) != IR_SUCCESS) return IR_ALREADY_INITIALIZED;
    char eInit = init_hashmap(&srSelf->hSymbols, sizeof(const char*), sizeof(struct ir_symbol*));
    if (eInit != HASHMAP_SUCCESS) return eInit;
    return IR_SUCCESS;
}

char symbol_refs_unsafe_get_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_irSymbol) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
    struct ir_symbol* found = 0;
    char eGetVal = symbol_refs_get_sibling_symbol_by_identifier(&srSelf->hSymbols, (void*)&pIdent, (void*)&found);
    if (eGetVal != IR_SUCCESS) return eGetVal;
    if (found != 0) return IR_SUCCESS;
    if (srSelf->srParent == 0) {
        *out_irSymbol = 0;
        return IR_SUCCESS;
    }
    return symbol_refs_unsafe_get_by_identifier(srSelf->srParent, pIdent, out_irSymbol);
}

char symbol_refs_unsafe_get_sibling_symbol_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_irSymbol) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
    struct ir_symbol* found = 0;
    char eGetVal = hashmap_get_value(&srSelf->hSymbols, (void*)&pIdent, (void*)&found);
    if (eGetVal == HASHMAP_SUCCESS) return IR_SUCCESS;
    if (eGetVal != HASHMAP_KEY_DOES_NOT_EXIST) return eGetVal;
    *out_irSymbol = 0;
    return IR_SUCCESS;
}

char symbol_refs_add_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* irSymbol) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
}

char deinit_scope_refs(struct scope_refs* srSelf) {
    char eDeInit = deinit_hashmap(&srSelf->hSymbols);
    if (eDeInit != HASHMAP_SUCCESS) return eDeInit;
    return IR_SUCCESS;
}

char declare_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* irSymbol) {
    struct ir_symbol* existingSymbol;
    char eGetExisting = symbol_refs_unsafe_get_sibling_symbol_by_identifier(srSelf, pIdent, &existingSymbol);
    if (eGetExisting != IR_SUCCESS) return eGetExisting;

    if (existingSymbol != 0) {
        // todo: throw error "symbol re-declared"
        return IR_SUCCESS; // we won't re-declare symbols
    }

    char eAddSymbol = symbol_refs_add_symbol(srSelf, pIdent, irSymbol);
    if (eAddSymbol != IR_SUCCESS) return eAddSymbol;
    return IR_SUCCESS;
}

char generate_intermediate_repr_var_decl(struct scope_refs* srThisScope, struct ast_elem* aeVarDecl) {
    if (aeVarDecl->iKind != AST_NODE_KIND_VAR_DECL_STMT) return IR_WRONG_NODE;
    const char* varName = 0;
    char eGetVarName = get_var_decl_stmt_var_name(aeVarDecl, &varName);
    if (eGetVarName != AST_NODE_SUCCESS) return eGetVarName;

    struct ast_elem* varInitializer = 0;
    char eGetInitializer = get_var_decl_stmt_var_initializer(aeVarDecl, &varInitializer);
    if (eGetInitializer != AST_NODE_SUCCESS) return eGetVarName;

    struct ir_sym_rtval* varDecl = new_sym_rtval();
    if (varDecl == 0) return IR_FAIL;

    char eDeclare = declare_symbol(srThisScope, varName, (struct ir_symbol*)varDecl);
    if (eDeclare != IR_SUCCESS) {
        free(varDecl);
        return eDeclare;
    }

    return IR_SUCCESS;
}

char generate_intermediate_hoisted_function_decl(struct scope_refs* srThisScope, struct ast_elem* aeRootElem) {

}

char generate_intermediate_repr_stmt_list(struct scope_refs* srThisScope, struct ast_elem* aeRootElem) {
    if (aeRootElem->iKind != AST_NODE_KIND_STMT_LIST) return IR_WRONG_NODE;

    struct ast_node* rootNode = (struct ast_node*)aeRootElem;
    for (int i = 0; i < rootNode->uNumElements; i++) {
        struct ast_elem* subNode = (struct node*)rootNode->ppElements[i];
        switch (subNode->iKind) {
        case AST_NODE_KIND_VAR_DECL_STMT:
            char eGenVarDecl = generate_intermediate_repr_var_decl(subNode);
            if (eGenVarDecl != IR_SUCCESS) return eGenVarDecl;
            break;
        }
    }
    return IR_SUCCESS;      
}