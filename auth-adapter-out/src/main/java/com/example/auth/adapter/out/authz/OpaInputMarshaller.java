package com.example.auth.adapter.out.authz;

import com.example.auth.application.authz.PolicyDecisionRequest;
import com.example.auth.application.authz.PolicyDecisionResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OPA REST API ({@code POST /v1/data/<policy>/<rule>}) 입력 / 출력 매핑.
 *
 * <p>OPA wire 형식 — request body: {@code {"input": <user-defined json>}},
 * response body: {@code {"result": <evaluated value>}}.
 *
 * <p>Rego 측에서 {@code input.subject.tenantId}, {@code input.resource.ownerUser} 처럼
 * 접근하므로 nested object 형태 그대로 직렬화합니다. UUID 는 Rego 의 string 비교에 그대로
 * 들어가도록 {@code asString()} 으로 변환.
 */
public final class OpaInputMarshaller {

    private OpaInputMarshaller() {
    }

    public static ObjectNode toInput(ObjectMapper om, PolicyDecisionRequest request) {
        ObjectNode root = om.createObjectNode();
        ObjectNode input = root.putObject("input");

        // subject
        ObjectNode subject = input.putObject("subject");
        subject.put("tenantId", request.subject().tenantId().asString());
        subject.put("userId", request.subject().userId().asString());
        var rolesArr = subject.putArray("roles");
        request.subject().roles().forEach(rolesArr::add);
        var permsArr = subject.putArray("permissions");
        request.subject().permissions().forEach(permsArr::add);
        if (!request.subject().attributes().isEmpty()) {
            subject.set("attributes", om.valueToTree(request.subject().attributes()));
        }

        // action
        input.put("action", request.action());

        // resource (nullable)
        if (request.resource() != null) {
            ObjectNode resource = input.putObject("resource");
            resource.put("type", request.resource().type());
            if (request.resource().ownerTenant() != null) {
                resource.put("ownerTenant", request.resource().ownerTenant().asString());
            }
            if (request.resource().ownerUser() != null) {
                resource.put("ownerUser", request.resource().ownerUser().asString());
            }
            if (!request.resource().attributes().isEmpty()) {
                resource.set("attributes", om.valueToTree(request.resource().attributes()));
            }
        }

        // context — 자유 형식 map. ip / userAgent / time 등이 들어옴.
        if (!request.context().isEmpty()) {
            input.set("context", om.valueToTree(request.context()));
        }
        return root;
    }

    /**
     * OPA 응답 파싱. 두 가지 응답 형태를 모두 처리:
     *
     * <ol>
     *   <li>document 단위 평가 (`/v1/data/auth/session/revoke`) — 응답 안에 allow / reasons 둘
     *       다 들어옴.</li>
     *   <li>rule 단위 평가 (`/v1/data/auth/session/revoke/allow`) — 응답이 단순 boolean.</li>
     * </ol>
     */
    public static PolicyDecisionResult parseResponse(JsonNode body) {
        if (body == null) {
            return PolicyDecisionResult.denied("opa_empty_response");
        }
        JsonNode result = body.get("result");
        if (result == null || result.isNull()) {
            // OPA 는 정책이 정의되지 않으면 result 없이 응답하기도 함. fail-closed.
            return PolicyDecisionResult.denied("opa_no_result");
        }

        if (result.isBoolean()) {
            return result.asBoolean()
                    ? PolicyDecisionResult.allowed()
                    : PolicyDecisionResult.denied("opa_disallow");
        }
        if (result.isObject()) {
            boolean allow = result.has("allow") && result.get("allow").asBoolean(false);
            List<String> reasons = new ArrayList<>();
            JsonNode reasonsNode = result.get("reasons");
            if (reasonsNode != null && reasonsNode.isArray()) {
                reasonsNode.forEach(n -> reasons.add(n.asText()));
            }
            Map<String, Object> obligations = new LinkedHashMap<>();
            JsonNode obligationsNode = result.get("obligations");
            if (obligationsNode != null && obligationsNode.isObject()) {
                obligationsNode.fieldNames().forEachRemaining(
                        f -> obligations.put(f, jsonNodeToObject(obligationsNode.get(f))));
            }
            if (allow) {
                return new PolicyDecisionResult(true, reasons, obligations);
            }
            if (reasons.isEmpty()) reasons.add("opa_disallow");
            return new PolicyDecisionResult(false, reasons, obligations);
        }
        return PolicyDecisionResult.denied("opa_unexpected_result_shape");
    }

    private static Object jsonNodeToObject(JsonNode node) {
        if (node == null || node.isNull()) return null;
        if (node.isTextual()) return node.asText();
        if (node.isBoolean()) return node.asBoolean();
        if (node.isInt() || node.isLong()) return node.asLong();
        if (node.isDouble() || node.isFloat()) return node.asDouble();
        return node.toString();
    }
}
