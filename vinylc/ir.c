#include "ir.h"
#include <stdlib.h>
#include <stdio.h>

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
    char eInit2 = init_vector(&srSelf->temporaryVars, 128, sizeof(struct ir_symbol*));
    if (eInit2 != VECTOR_SUCCESS) return eInit2;
    return IR_SUCCESS;
}

char symbol_refs_unsafe_get_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_symSymbol) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
    struct ir_symbol* found = 0;
    char eGetVal = symbol_refs_unsafe_get_sibling_symbol_by_identifier(srSelf, (void*)&pIdent, (void*)&found);
    if (eGetVal != IR_SUCCESS) return eGetVal;
    if (found != 0) return IR_SUCCESS;
    if (srSelf->srParent == 0) {
        return IR_SUCCESS;
    }
    return symbol_refs_unsafe_get_by_identifier(srSelf->srParent, pIdent, out_symSymbol);
}

char symbol_refs_unsafe_get_sibling_symbol_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_symSymbol) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
    struct ir_symbol* found = 0;
    char eGetVal = hashmap_get_value(&srSelf->hSymbols, (void*)&pIdent, (void*)&found);
    if (eGetVal == HASHMAP_SUCCESS) return IR_SUCCESS;
    if (eGetVal != HASHMAP_KEY_DOES_NOT_EXIST) return eGetVal;
    return IR_SUCCESS;
}

char symbol_refs_add_tmp_symbol(struct scope_refs* srSelf, struct ir_sym* symSymbol) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
    char eAppend = vector_append(&srSelf->temporaryVars, symSymbol);
    if (eAppend != VECTOR_SUCCESS) return eAppend;
    return IR_SUCCESS;
}

char symbol_refs_add_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* symSymbol) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
}

char deinit_scope_refs(struct scope_refs* srSelf) {
    if (scope_refs_assert_not_initialized(srSelf) == IR_SUCCESS) return IR_NOT_INITIALIZED;
    char eDeInit = deinit_hashmap(&srSelf->hSymbols);
    if (eDeInit != HASHMAP_SUCCESS) return eDeInit;
    for (int i = 0; i < srSelf->temporaryVars.uLength; i++) {
        const char* str = 0;
        vector_at(&srSelf->temporaryVars, i, &str);
        if (str != 0) {
            free(str);
        }
    }
    return IR_SUCCESS;
}

CREATE_VAR_STRUCT_FUNCTION(ir_expr_ref, expr_ref) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_expr_ref, IR_EXPR_KIND_REF);
CREATE_VAR_STRUCT_FUNCTION(ir_expr_const, expr_const) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_expr_const, IR_EXPR_KIND_CONST);
CREATE_VAR_STRUCT_FUNCTION(ir_expr_static_access, expr_static_access) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_expr_static_access, IR_EXPR_KIND_STATIC_ACCESS);
CREATE_VAR_STRUCT_FUNCTION(ir_expr_operation, expr_operation) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_expr_operation, IR_EXPR_KIND_OPERATION);
NEW_VAR_STRUCT_FUNCTION(ir_expr_ref, expr_ref) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_expr_ref, expr_ref);
NEW_VAR_STRUCT_FUNCTION(ir_expr_const, expr_const) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_expr_const, expr_const);
NEW_VAR_STRUCT_FUNCTION(ir_expr_static_access, expr_static_access) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_expr_static_access, expr_static_access);
NEW_VAR_STRUCT_FUNCTION(ir_expr_operation, expr_operation) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_expr_operation, expr_operation);

char deinit_expr(struct ir_expr* eExpr) {
    if (eExpr == 0) return IR_SUCCESS;
    switch (eExpr->iKind) {
    case IR_EXPR_KIND_NIL: break;
    case IR_EXPR_KIND_REF: break;
    case IR_EXPR_KIND_CONST:
        free(((struct ir_expr_const*)eExpr)->pStringVal);
        break;
    case IR_EXPR_KIND_STATIC_ACCESS:
        deinit_expr(((struct ir_expr_static_access*)eExpr)->eBase);
        deinit_expr(((struct ir_expr_static_access*)eExpr)->eProperty);
        break;
    case IR_EXPR_KIND_OPERATION:
        deinit_expr(((struct ir_expr_operation*)eExpr)->eOperand1);
        deinit_expr(((struct ir_expr_operation*)eExpr)->eOperand2);
        break;
    }
    free(eExpr);
    return IR_SUCCESS;
}

CREATE_VAR_STRUCT_FUNCTION(ir_instruct_noop, instruct_noop) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_noop, IR_INSTRUCT_NOOP);
CREATE_VAR_STRUCT_FUNCTION(ir_instruct_call, instruct_call) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_call, IR_INSTRUCT_KIND_CALL);
CREATE_VAR_STRUCT_FUNCTION(ir_instruct_assign, instruct_assign) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_assign, IR_INSTRUCT_KIND_ASSIGN);
CREATE_VAR_STRUCT_FUNCTION(ir_instruct_cond, instruct_cond) CREATE_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_cond, IR_INSTRUCT_KIND_COND);
NEW_VAR_STRUCT_FUNCTION(ir_instruct_noop, instruct_noop) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_noop, instruct_noop);
nEW_VAR_STRUCT_FUNCTION(ir_instruct_call, instruct_call) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_call, instruct_call);
NEW_VAR_STRUCT_FUNCTION(ir_instruct_assign, instruct_assign) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_assign, instruct_assign);
NEW_VAR_STRUCT_FUNCTION(ir_instruct_cond, instruct_cond) NEW_VAR_STRUCT_FUNCTION_IMPL(ir_instruct_cond, instruct_cond);

struct ir_instruct_list create_instruction_list() {
    struct ir_instruct_list out = {};
    return out;
}

struct ir_instruct_list* new_instruction_list() {
    struct ir_instruct_list* list = (struct ir_instruct_list*)malloc(sizeof(struct ir_instruct_list));
    *list = create_instruction_list();
    return list;
}

char instruction_list_assert_not_initialized(struct ir_instruct_list* ilSelf) {
    return vector_assert_not_initialized(&ilSelf->vInstructions) ? VECTOR_SUCCESS : VECTOR_FAIL;
}

char init_instruction_list(struct ir_instruct_list* ilSelf) {
    if (instruction_list_assert_not_initialized(ilSelf) != VECTOR_SUCCESS) return IR_ALREADY_INITIALIZED;
    init_vector(&ilSelf->vInstructions, 512, sizeof(struct ir_instruct*));
    return IR_SUCCESS;
}

char instruction_list_new(struct ir_instruct_list* ilSelf, NEW_INSTRUCTION_FUNCTION((*fpNewInstruction)), struct ir_instruct** out_iInstruction) {
    if (instruction_list_assert_not_initialized(ilSelf) != VECTOR_FAIL) return IR_NOT_INITIALIZED;
    struct ir_instruct* instruction = fpNewInstruction();
    if (instruction == 0) return IR_FAIL;
    char eAppend = vector_append(ilSelf, (void*)&instruction);
    if (eAppend != VECTOR_SUCCESS) return eAppend;
    *out_iInstruction = instruction;
    return IR_SUCCESS;
}

char deinit_instruction_list(struct ir_instruct_list* ilSelf) {
    if (instruction_list_assert_not_initialized(ilSelf) != VECTOR_FAIL) return IR_NOT_INITIALIZED;
    deinit_vector(&ilSelf->vInstructions);
    return IR_SUCCESS;
}

char declare_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* irSymbol) {
    struct ir_sym* existingSymbol;
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

PROCESS_TYPE_AND_EXPR_FUNCTION(literal, ast_literal) {
    struct ast_literal* lit = aeRootElem;
    switch (lit->iLiteralKind) {
    case AST_LITERAL_KIND_STR:
    case AST_LITERAL_KIND_NUM:
        struct ir_sig_magic* magicType = new_sig_magic();
        if (magicType == 0) return IR_FAIL;
        struct ir_expr_const* constExpr = new_expr_const();
        if (constExpr == 0) {
            free(magicType);
            return IR_FAIL;
        }
        magicType->iCompilerMagic = lit->iLiteralKind == AST_LITERAL_KIND_STR
            ? IR_TYPE_MAGIC_REF_STR
            : IR_TYPE_MAGIC_REF_NUM;
        constExpr->iConstType = lit->iLiteralKind == AST_LITERAL_KIND_STR
            ? IR_CONST_KIND_STR
            : IR_CONST_KIND_NUM;
        constExpr->pStringVal = lit->tToken->pContent;
        if (out_eExpr != 0) *out_eExpr = constExpr;
        if (out_sType != 0) *out_sType = magicType;
        break;
    case AST_LITERAL_KIND_IDENT:
        struct ir_sym* varSymbol = 0;
        char eGetRef = symbol_refs_unsafe_get_by_identifier(srThisScope, lit->tToken->pContent, &varSymbol);
        if (eGetRef != IR_SUCCESS) return eGetRef;
        // todo: mark function as first-class
        struct ir_expr_ref* refExpr = new_expr_ref();
        if (refExpr == 0) return IR_FAIL;
        switch (varSymbol->iKind) {
        case IR_SYMBOL_KIND_RTVAL:
            struct ir_sym_rtval* runtimeVal = (struct ir_sym_rtval*)varSymbol;
            refExpr->symRef = runtimeVal;
            if (out_eExpr != 0) *out_eExpr = refExpr;
            if (out_sType != 0) *out_sType = runtimeVal->tsType;
            break;
        case IR_SYMBOL_KIND_NIL:
        case IR_SYMBOL_KIND_TYPEREF:
            // type unknown
            break;
        }
        break;
    case AST_LITERAL_KIND_NIL:
    case AST_LITERAL_KIND_OPER:
        // type unknown
        break;
    }
}

PROCESS_TYPE_AND_EXPR_FUNCTION(binary_oper, ast_node) {

}

PROCESS_TYPE_AND_EXPR_FUNCTION(unary_oper, ast_node) {

}

PROCESS_TYPE_AND_EXPR_FUNCTION(par, ast_node) {
    struct ast_node* parNode = aeRootElem;
    for (int i = 0; i < parNode->uNumElements; i++) {
        char eInfer = infer_type_and_get_return_expr(srThisScope, ilInstructions, parNode->ppElements[i], out_sType, out_eExpr);
        if (eInfer != 0) return eInfer;
    }
    return IR_SUCCESS;
}

PROCESS_TYPE_AND_EXPR_FUNCTION(call, ast_node) {
    struct ast_node* callNode = aeRootElem;
    struct ast_elem* functionRef = 0;
    char eGetFunctionRef = get_call_function_ref(aeRootElem, &functionRef);
    if (eGetFunctionRef != AST_NODE_SUCCESS) return eGetFunctionRef;

    struct ir_sig* callReturnType;
    struct ir_expr* functionExpr;
    
    struct ir_sym_rtval* tmpSymbol = new_sym_rtval();
    if (tmpSymbol == 0) return IR_FAIL;

    if (functionRef->iKind == AST_NODE_KIND_LITERAL) {
        struct ir_sym* funcSymbol = 0;
        struct ast_literal* refLit = (struct ast_literal*)functionRef;
        char eGetRef = symbol_refs_unsafe_get_by_identifier(srThisScope, refLit->tToken->pContent, &funcSymbol);
        if (eGetRef != IR_SUCCESS) {
            free(tmpSymbol);
            return eGetRef;
        }
        switch (funcSymbol->iKind) {
        case IR_SYMBOL_KIND_RTVAL:
            struct ir_sym_rtval* runtimeFuncVal = (struct ir_sym_rtval*)funcSymbol;
            switch (runtimeFuncVal->tsType->iKind) {
            case IR_TYPE_SIGNATURE_KIND_PROC:
                struct ir_sig_proc* procSig = (struct ir_sig_proc*)runtimeFuncVal->tsType;
                callReturnType = procSig->tsRetType;
                if (out_sType != 0) *out_sType = callReturnType;

                struct ir_expr_ref* refExpr = new_expr_ref();
                if (refExpr == 0) {
                    free(tmpSymbol);
                    return IR_FAIL;
                }
                refExpr->symRef = funcSymbol;
                functionExpr = refExpr;
                break;
            case IR_TYPE_SIGNATURE_KIND_NIL:
            case IR_TYPE_SIGNATURE_KIND_MAGIC:
            case IR_TYPE_SIGNATURE_KIND_OBJECT:
            case IR_TYPE_SIGNATURE_KIND_REF:
                // type unknown
                break;
            }
            break;
        case IR_SYMBOL_KIND_NIL:
        case IR_SYMBOL_KIND_TYPEREF:
            // type unknown
            break;
        }
    } else {
        struct ir_sig* functionRefType = 0;
        char eInferCall = infer_type_and_get_return_expr(srThisScope, ilInstructions, eGetFunctionRef, &functionRefType, &functionExpr);
        if (eInferCall != IR_SUCCESS) {
            free(tmpSymbol);
            return eInferCall;
        }

        if (functionRefType != 0 && functionRefType->iKind == IR_TYPE_SIGNATURE_KIND_PROC) {
            struct ir_sig_proc* functionRefProc = (struct ir_sig_proc*)functionRefType;
            callReturnType = functionRefProc->tsRetType;
        } else {
            // type unknown
        }
    }

    tmpSymbol->tsType = callReturnType;
    char eAddTmp = symbol_refs_add_tmp_symbol(srThisScope, tmpSymbol);
    if (eAddTmp != IR_SUCCESS) return eAddTmp;

    struct ir_instruct_call* callInstruct = new_instruct_call();
    if (callInstruct == 0) {
        free(tmpSymbol);
        return IR_FAIL;
    }
    callInstruct->symTemp = tmpSymbol;
    callInstruct->symFunctionRef = functionExpr;

    struct ast_elem* callParams;
    char eGetParams = get_call_params(aeRootElem, &callParams);
    if (eGetParams != AST_NODE_SUCCESS) {
        free(tmpSymbol);
        free(callInstruct);
        return eGetParams;
    }
    if (callParams->iKind == AST_NODE_KIND_PAR) {
        struct ast_node* paramsNode = (struct ast_node*)callParams;
        callInstruct->peActualParamExpr = (struct ir_expr**)malloc(paramsNode->uNumElements * sizeof(struct ir_expr*));
        for (int i = 0; i < paramsNode->uNumElements; i++) {
            struct ast_elem* paramElem = paramsNode->ppElements[i];
            // todo: verify parameter type
            char eInfer = infer_type_and_get_return_expr(srThisScope, ilInstructions, aeRootElem, 0, &callInstruct->peActualParamExpr[i]);
            if (eInfer != IR_SUCCESS) {
                free(tmpSymbol);
                free(callInstruct->peActualParamExpr);
                free(callInstruct);
                return eInfer;
            }
        }
    }
    
    if (out_eExpr != 0) {
        struct ir_expr_ref* returnRef = new_expr_ref();
        if (returnRef == 0) {
            free(tmpSymbol);
            deinit_expr(callInstruct->peActualParamExpr);
            free(callInstruct);
            deinit_expr(returnRef);
            return IR_FAIL;
        }
        *out_eExpr = returnRef;
    }
    return IR_SUCCESS;
}

PROCESS_TYPE_AND_EXPR_FUNCTION(any, ast_elem) {
    switch (aeRootElem->iKind) {
    case AST_NODE_KIND_LITERAL:
        process_literal_type_and_expr(srThisScope, ilInstructions, (struct ast_literal*)aeRootElem, out_sType, out_eExpr);
        break;
    case AST_NODE_KIND_BINARY_OPER:
        process_binary_type_and_expr(srThisScope, ilInstructions, (struct ast_node*)aeRootElem, out_sType, out_eExpr);
        break;
    case AST_NODE_KIND_UNARY_OPER:
        process_unary_type_and_expr(srThisScope, ilInstructions, (struct ast_node*)aeRootElem, out_sType, out_eExpr);
        break;
    case AST_NODE_KIND_PAR:
        process_par_type_and_expr(srThisScope, ilInstructions, (struct ast_node*)aeRootElem, out_sType, out_eExpr);
        break;
    case AST_NODE_KIND_TUPLE:
        break;
    case AST_NODE_KIND_CALL:
        process_call_type_and_expr(srThisScope, ilInstructions, (struct ast_node*)aeRootElem, out_sType, out_eExpr);
        break;
    case AST_NODE_KIND_EMPTY:
    case AST_NODE_KIND_STMT_LIST:
    case AST_NODE_KIND_VAR_DECL_STMT:
    case AST_NODE_KIND_BLOCK:
    case AST_NODE_KIND_FUNCTION_DECL_STMT:
    case AST_NODE_KIND_RETURN_STMT:
    case AST_NODE_KIND_IF_STMT:
    case AST_NODE_KIND_ELSE_STMT:
        // type unknown
        break;
    }
    if (*out_sType == 0) {
        struct ir_sig_magic* magicType = new_sig_magic();
        if (magicType == 0) return IR_FAIL;
        magicType->iCompilerMagic = IR_TYPE_MAGIC_REF_UNKNOWN;
        *out_sType = magicType;
    }
    return AST_NODE_SUCCESS;
}

char generate_ir_var_decl(struct scope_refs* srThisScope, struct ir_instruct_list* ilInstructions, struct ast_elem* aeVarDecl) {
    if (aeVarDecl->iKind != AST_NODE_KIND_VAR_DECL_STMT) return IR_WRONG_NODE;
    const char* varName = 0;
    char eGetVarName = get_var_decl_stmt_var_name(aeVarDecl, &varName);
    if (eGetVarName != AST_NODE_SUCCESS) return eGetVarName;

    struct ast_elem* varInitializer = 0;
    char eGetInitializer = get_var_decl_stmt_var_initializer(aeVarDecl, &varInitializer);
    if (eGetInitializer != AST_NODE_SUCCESS) return eGetVarName;

    struct ir_sig* initializerType = 0;
    struct ir_expr* initializerExpr = 0;

    char eProcess = process_any_type_and_expr(srThisScope, ilInstructions, varInitializer, &initializerType, &initializerExpr);
    if (eProcess != IR_SUCCESS) return eProcess;

    struct ir_sym_rtval* varDecl = new_sym_rtval();
    if (varDecl == 0) return IR_FAIL;
    varDecl->tsType = initializerType;

    char eDeclare = declare_symbol(srThisScope, varName, (struct ir_sym*)varDecl);
    if (eDeclare != IR_SUCCESS) {
        free(initializerType);
        deinit_expr(initializerExpr);
        free(varDecl);
        return eDeclare;
    }
    
    struct ir_instruct_assign* assignmentInst = 0;
    char eNewInstr = instruction_list_new(ilInstructions, new_instruct_assign, (struct ir_instruct**)&assignmentInst);
    if (eNewInstr != IR_SUCCESS) {
        return eNewInstr;
    }
    assignmentInst->eAssignee = varDecl;
    assignmentInst->eVal = initializerExpr;

    return IR_SUCCESS;
}

char generate_ir_hoisted_function_decl(struct scope_refs* srThisScope, struct ir_instruct_list* ilInstructions, struct ast_elem* aeRootElem) {

}

char generate_ir_stmt_list(struct scope_refs* srThisScope, struct ir_instruct_list* ilInstructions, struct ast_elem* aeRootElem) {
    if (aeRootElem->iKind != AST_NODE_KIND_STMT_LIST) return IR_WRONG_NODE;

    struct ast_node* rootNode = (struct ast_node*)aeRootElem;
    for (int i = 0; i < rootNode->uNumElements; i++) {
        struct ast_elem* subNode = (struct ast_elem*)rootNode->ppElements[i];
        switch (subNode->iKind) {
        case AST_NODE_KIND_VAR_DECL_STMT:
            char eGenVarDecl = generate_ir_var_decl(srThisScope, ilInstructions, subNode);
            if (eGenVarDecl != IR_SUCCESS) return eGenVarDecl;
            break;
        }
    }
    return IR_SUCCESS;      
}