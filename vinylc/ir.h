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
#define IR_TYPE_MAGIC_REF_UNKNOWN (char)1
#define IR_TYPE_MAGIC_REF_NUM (char)2
#define IR_TYPE_MAGIC_REF_STR (char)3

#define IR_SYMBOL_KIND_NIL (char)0
#define IR_SYMBOL_KIND_RTVAL (char)1
#define IR_SYMBOL_KIND_TYPEREF (char)2

#define IR_EXPRESSION_KIND_NIL (char)0
#define IR_EXPRESSION_KIND_ADD (char)1

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
    struct ir_sig* tsRef;
};

struct ir_sig_proc {
    char iKind;
    struct vector vFormalParams;
    struct ir_sig* tsRetType;
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
    struct ir_sig* tsType;
};

struct ir_sym_typeref {
    char iKind;
    struct ir_sig* tsRef;
};

struct scope_refs {
    struct scope_refs* srParent;
    struct hashmap hSymbols;
    struct vector temporaryVars;
};

CREATE_VAR_STRUCT_FUNCTION(ir_sym_rtval, sym_rtval);
CREATE_VAR_STRUCT_FUNCTION(ir_sym_typeref, sym_typeref);
NEW_VAR_STRUCT_FUNCTION(ir_sym_rtval, sym_rtval);
NEW_VAR_STRUCT_FUNCTION(ir_sym_typeref, sym_typeref);

struct scope_refs create_scope_refs(struct scope_refs* srParent);
char scope_refs_assert_not_initialized(struct scope_refs* srSelf);
char init_scope_refs(struct scope_refs* srSelf);
char symbol_refs_unsafe_get_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_symSymbol);
char symbol_refs_unsafe_get_sibling_symbol_by_identifier(struct scope_refs* srSelf, const char* pIdent, struct ir_sym** out_symSymbol);
char symbol_refs_add_tmp_symbol(struct scope_refs* srSelf, struct ir_sym* symSymbol);
char symbol_refs_add_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* symSymbol);
char deinit_scope_refs(struct scope_refs* srSelf);

#define IR_EXPR_KIND_NIL (char)0
#define IR_EXPR_KIND_REF (char)1
#define IR_EXPR_KIND_CONST (char)2
#define IR_EXPR_KIND_STATIC_ACCESS (char)3
#define IR_EXPR_KIND_OPERATION (char)4

#define IR_OPERATION_KIND_NIL (char)0
#define IR_OPERATION_KIND_ADD (char)1
#define IR_OPERATION_KIND_SUB (char)2
#define IR_OPERATION_KIND_MUL (char)3
#define IR_OPERATION_KIND_DIV (char)4
#define IR_OPERATION_KIND_MOD (char)5
#define IR_OPERATION_KIND_AND (char)6
#define IR_OPERATION_KIND_OR (char)7
#define IR_OPERATION_KIND_EQ (char)8
#define IR_OPERATION_KIND_GT (char)9
#define IR_OPERATION_KIND_LT (char)10

#define IR_INSTRUCT_KIND_NIL (char)0
#define IR_INSTRUCT_NOOP (char)1
#define IR_INSTRUCT_KIND_CALL (char)2
#define IR_INSTRUCT_KIND_ASSIGN (char)3
#define IR_INSTRUCT_KIND_COND (char)4

#define IR_CONST_KIND_NIL (char)0
#define IR_CONST_KIND_STR (char)1
#define IR_CONST_KIND_NUM (char)2

struct ir_expr {
    char iKind;
};

struct ir_expr_ref {
    char iKind;
    struct ir_sym_rtval* symRef;
};

struct ir_expr_const {
    char iKind;
    char iConstType;
    const char* pStringVal;
};

struct ir_expr_static_access {
    char iKind;
    struct ir_expr* eBase;
    struct ir_expr_const* eProperty;
};

struct ir_expr_operation {
    char iKind;
    char iOperationKind;
    struct ir_expr* eOperand1;
    struct ir_expr* eOperand2;
};

CREATE_VAR_STRUCT_FUNCTION(ir_expr_ref, expr_ref);
CREATE_VAR_STRUCT_FUNCTION(ir_expr_const, expr_const);
CREATE_VAR_STRUCT_FUNCTION(ir_expr_static_access, expr_static_access);
CREATE_VAR_STRUCT_FUNCTION(ir_expr_operation, expr_operation);
NEW_VAR_STRUCT_FUNCTION(ir_expr_ref, expr_ref);
NEW_VAR_STRUCT_FUNCTION(ir_expr_const, expr_const);
NEW_VAR_STRUCT_FUNCTION(ir_expr_static_access, expr_static_access);
NEW_VAR_STRUCT_FUNCTION(ir_expr_operation, expr_operation);

char deinit_expr(struct ir_expr* eExpr);

struct ir_instruct_list {
    struct vector vInstructions;
};

struct ir_instruct {
    char iKind;
};

#define NEW_INSTRUCTION_FUNCTION(NAME) struct ir_instruct* NAME()
struct ir_instruct_list create_instruction_list();
struct ir_instruct_list* new_instruction_list();
char instruction_list_assert_not_initialized(struct ir_instruct_list* ilSelf);
char init_instruction_list(struct ir_instruct_list* ilSelf);
char instruction_list_new(struct ir_instruct_list* ilSelf, NEW_INSTRUCTION_FUNCTION((*fpNewInstruction)), struct ir_instruct** out_iInstruction);
char deinit_instruction_list(struct ir_instruct_list* ilSelf);

struct ir_instruct_noop {
    char iKind;
    struct ir_expr* eExpr;
};

struct ir_instruct_call {
    char iKind;
    struct ir_sym_rtval* symTemp;
    struct ir_expr* symFunctionRef;
    struct ir_expr** peActualParamExpr;
};

struct ir_instruct_assign {
    char iKind;
    struct ir_expr* eAssignee;
    struct ir_expr* eVal;
};

struct ir_instruct_cond {
    char iKind;
    struct ir_expr* eCond;
    struct ir_instruct_list* iThenBranch;
    struct ir_instruct_list* iElseBranch;
};

CREATE_VAR_STRUCT_FUNCTION(ir_instruct_noop, instruct_noop);
CREATE_VAR_STRUCT_FUNCTION(ir_instruct_call, instruct_call);
CREATE_VAR_STRUCT_FUNCTION(ir_instruct_assign, instruct_assign);
CREATE_VAR_STRUCT_FUNCTION(ir_instruct_cond, instruct_cond);
NEW_VAR_STRUCT_FUNCTION(ir_instruct_noop, instruct_noop);
NEW_VAR_STRUCT_FUNCTION(ir_instruct_call, instruct_call);
NEW_VAR_STRUCT_FUNCTION(ir_instruct_assign, instruct_assign);
NEW_VAR_STRUCT_FUNCTION(ir_instruct_cond, instruct_cond);

char declare_symbol(struct scope_refs* srSelf, const char* pIdent, struct ir_sym* irSymbol);

#define PROCESS_TYPE_AND_EXPR_FUNCTION(NAME, AST_STRUCT_TYPE) char process_##NAME##_type_and_expr(struct scope_refs* srThisScope, struct ir_instruct_list* ilInstructions, struct AST_STRUCT_TYPE* aeRootElem, struct ir_sig** out_sType, struct ir_expr** out_eExpr)

PROCESS_TYPE_AND_EXPR_FUNCTION(literal, ast_literal);
PROCESS_TYPE_AND_EXPR_FUNCTION(binary_oper, ast_node);
PROCESS_TYPE_AND_EXPR_FUNCTION(unary_oper, ast_node);
PROCESS_TYPE_AND_EXPR_FUNCTION(par, ast_node);
PROCESS_TYPE_AND_EXPR_FUNCTION(call, ast_node);
PROCESS_TYPE_AND_EXPR_FUNCTION(any, ast_elem);
char generate_ir_var_decl(struct scope_refs* srThisScope, struct ir_instruct_list* ilInstructions, struct ast_elem* aeVarDecl);
char generate_ir_hoisted_function_decl(struct scope_refs* srThisScope, struct ir_instruct_list* ilInstructions, struct ast_elem* aeRootElem);
char generate_ir_stmt_list(struct scope_refs* srThisScope, struct ir_instruct_list* ilInstructions, struct ast_elem* aeRootElem);

#endif // IR_H  