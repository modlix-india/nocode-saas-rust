import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import com.fincity.saas.commons.core.document.Storage;
import com.fincity.saas.commons.core.model.StorageRelation;
import com.fincity.saas.commons.core.enums.StorageRelationType;
import com.fincity.saas.commons.core.service.CoreMessageResourceService;
import com.fincity.saas.commons.core.service.connection.appdata.MongoAppDataService;
import com.fincity.saas.commons.core.service.connection.appdata.mysql.*;
import com.fincity.saas.commons.jackson.CommonsSerializationModule;
import com.fincity.saas.commons.jackson.SortSerializationModule;
import com.fincity.saas.commons.model.AggregateQuery;
import com.fincity.saas.commons.model.condition.AbstractCondition;
import org.bson.conversions.Bson;
import org.bson.json.JsonMode;
import org.bson.json.JsonWriterSettings;
import org.jooq.*;
import org.jooq.impl.DSL;
import reactor.core.publisher.Mono;
import java.lang.reflect.Method;

import java.util.*;

/**
 * Runs the Java app-data builders over the cases in a JSON file and prints what they
 * produce, so the Rust ports can be compared with the real thing rather than with a
 * transcription of it. Read-only: nothing here touches a database.
 *
 * Usage: java -cp <commons-core classpath>:. Oracle cases.json expected.json
 */
public class Oracle {

    static final ObjectMapper M = new ObjectMapper()
            .registerModule(new CommonsSerializationModule())
            .registerModule(new SortSerializationModule())
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    static final DSLContext C = DSL.using(SQLDialect.MYSQL);

    public static void main(String[] args) throws Exception {
        JsonNode cases = M.readTree(java.nio.file.Files.readString(java.nio.file.Path.of(args[0])));
        ObjectNode out = M.createObjectNode();
        out.set("mysqlFilters", mysqlFilters(cases.path("mysqlFilters")));
        out.set("mongoFilters", mongoFilters(cases.path("mongoFilters")));
        out.set("mysqlAggregates", mysqlAggregates(cases.path("mysqlAggregates")));
        out.set("mongoAggregates", mongoAggregates(cases.path("mongoAggregates")));
        out.set("jsonShapes", jsonShapes());
        java.nio.file.Files.writeString(java.nio.file.Path.of(args[1]), M.writerWithDefaultPrettyPrinter().writeValueAsString(out));
    }

    static Set<String> set(JsonNode n) {
        Set<String> s = new LinkedHashSet<>();
        if (n != null) n.forEach(e -> s.add(e.asText()));
        return s;
    }

    static AbstractCondition condition(JsonNode n) throws Exception {
        if (n == null || n.isMissingNode() || n.isNull()) return null;
        return M.treeToValue(n, AbstractCondition.class);
    }

    static ObjectNode error(ObjectNode r, Throwable e) {
        Throwable t = e;
        while (t.getCause() != null && !(t instanceof UnsupportedFilterException)
                && !(t instanceof com.fincity.saas.commons.exeception.GenericException)) t = t.getCause();
        ObjectNode err = r.putObject("error");
        err.put("class", t.getClass().getSimpleName());
        if (t instanceof UnsupportedFilterException u) {
            err.put("malformed", u.isMalformed());
            err.put("detail", u.getDetail());
        } else if (t instanceof com.fincity.saas.commons.exeception.GenericException g) {
            err.put("status", g.getStatusCode().value());
            err.put("detail", g.getMessage());
        } else {
            err.put("detail", String.valueOf(t.getMessage()));
        }
        return r;
    }

    static ArrayNode binds(QueryPart q) {
        ArrayNode a = M.createArrayNode();
        for (Object o : C.extractBindValues(q)) a.add(M.valueToTree(o));
        return a;
    }

    static ArrayNode mysqlFilters(JsonNode cases) {
        ArrayNode out = M.createArrayNode();
        for (JsonNode c : cases) {
            ObjectNode r = out.addObject();
            r.put("name", c.get("name").asText());
            try {
                MySQLFieldResolver resolver = MySQLFieldResolver.of(set(c.get("json")))
                        .withTextColumns(set(c.get("text")))
                        .withStemming(!c.has("stemming") || c.get("stemming").asBoolean());
                AbstractCondition cond = condition(c.get("condition"));
                Condition built = "delete".equals(c.path("mode").asText())
                        ? MySQLFilterBuilder.build(cond, resolver)
                        : MySQLFilterBuilder.buildForRead(cond, resolver);
                r.put("inlined", C.renderInlined(built));
                r.put("sql", C.render(built));
                r.set("binds", binds(built));
            } catch (Throwable e) {
                error(r, e);
            }
        }
        return out;
    }

    static ArrayNode mongoFilters(JsonNode cases) throws Exception {
        ArrayNode out = M.createArrayNode();
        MongoAppDataService svc = new MongoAppDataService(null, null, null, new CoreMessageResourceService(), null, null, null, null);
        Method filter = MongoAppDataService.class.getDeclaredMethod("filter", Storage.class, AbstractCondition.class);
        filter.setAccessible(true);
        JsonWriterSettings canonical = JsonWriterSettings.builder().outputMode(JsonMode.EXTENDED).build();
        for (JsonNode c : cases) {
            ObjectNode r = out.addObject();
            r.put("name", c.get("name").asText());
            try {
                Storage storage = new Storage();
                storage.setName("s");
                Map<String, StorageRelation> rel = new LinkedHashMap<>();
                for (String f : set(c.get("relations")))
                    rel.put(f, new StorageRelation().setStorageName("t").setRelationType(StorageRelationType.TO_ONE));
                storage.setRelations(rel);
                @SuppressWarnings("unchecked")
                Mono<Bson> m = (Mono<Bson>) filter.invoke(svc, storage, condition(c.get("condition")));
                Bson b = m.block();
                r.set("bson", M.readTree(b.toBsonDocument().toJson(canonical)));
            } catch (java.lang.reflect.InvocationTargetException e) {
                error(r, e.getCause());
            } catch (Throwable e) {
                error(r, e);
            }
        }
        return out;
    }

    static ArrayNode mysqlAggregates(JsonNode cases) {
        ArrayNode out = M.createArrayNode();
        Table<?> table = DSL.table(DSL.name("db", "orders"));
        for (JsonNode c : cases) {
            ObjectNode r = out.addObject();
            r.put("name", c.get("name").asText());
            try {
                AggregateQuery q = M.treeToValue(c.get("query"), AggregateQuery.class);
                MySQLFieldResolver resolver = MySQLFieldResolver.of(set(c.get("json")));
                Condition where = MySQLFilterBuilder.buildForRead(q.getCondition(), resolver);
                Condition having = q.getHaving() == null ? null : MySQLFilterBuilder.build(q.getHaving(), Set.of());
                r.put("page", C.renderInlined(MySQLAggregateBuilder.page(C, table, q, where, having, q.getPageable(), resolver)));
                r.put("count", C.renderInlined(MySQLAggregateBuilder.count(C, table, q, where, having, resolver)));
            } catch (Throwable e) {
                error(r, e);
            }
        }
        return out;
    }

    static ArrayNode mongoAggregates(JsonNode cases) throws Exception {
        ArrayNode out = M.createArrayNode();
        MongoAppDataService svc = new MongoAppDataService(null, null, null, new CoreMessageResourceService(), null, null, null, null);
        Method group = MongoAppDataService.class.getDeclaredMethod("groupStage", AggregateQuery.class);
        Method project = MongoAppDataService.class.getDeclaredMethod("projectStage", AggregateQuery.class);
        group.setAccessible(true);
        project.setAccessible(true);
        JsonWriterSettings canonical = JsonWriterSettings.builder().outputMode(JsonMode.EXTENDED).build();
        for (JsonNode c : cases) {
            ObjectNode r = out.addObject();
            r.put("name", c.get("name").asText());
            try {
                AggregateQuery q = M.treeToValue(c.get("query"), AggregateQuery.class);
                r.set("group", M.readTree(((Bson) group.invoke(svc, q)).toBsonDocument().toJson(canonical)));
                r.set("project", M.readTree(((Bson) project.invoke(svc, q)).toBsonDocument().toJson(canonical)));
            } catch (Throwable e) {
                error(r, e);
            }
        }
        return out;
    }

    /**
     * The drift and migration records as the services' ObjectMapper writes them
     * (AbstractBaseConfiguration: NON_EMPTY values, the commons modules), compact.
     */
    static ObjectNode jsonShapes() throws Exception {
        ObjectMapper w = new ObjectMapper()
                .setDefaultPropertyInclusion(com.fasterxml.jackson.annotation.JsonInclude.Value.construct(
                        com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY,
                        com.fasterxml.jackson.annotation.JsonInclude.Include.ALWAYS))
                .registerModule(new CommonsSerializationModule())
                .registerModule(new SortSerializationModule());
        String db = "A_app", t = "app_t";
        List<SchemaChange> changes = List.of(
                new SchemaChange(SchemaChange.Kind.DESTRUCTIVE, "old", "VARCHAR(10)", null, "not in the definition"),
                new SchemaChange(SchemaChange.Kind.WIDENING, "n", "INT", "BIGINT", "wider"),
                new SchemaChange(SchemaChange.Kind.NARROWING, "s", "VARCHAR(50)", "VARCHAR(20)", "shorter", "utf8mb4_bin"));
        List<String> idx = List.of("ALTER TABLE `A_app`.`app_t` DROP INDEX `i`", "CREATE INDEX `j` ON `A_app`.`app_t` (`n`)");
        List<String> fks = List.of("ALTER TABLE `A_app`.`app_t` DROP FOREIGN KEY `fk`");
        ObjectNode o = M.createObjectNode();
        o.put("reportClean", w.writeValueAsString(new MySQLDrift.Report(db, t, true, List.of(), List.of(), List.of())));
        o.put("reportMissing", w.writeValueAsString(new MySQLDrift.Report(db, t, false, List.of(), List.of(), List.of())));
        o.put("reportDirty", w.writeValueAsString(new MySQLDrift.Report(db, t, true, changes, idx, fks)));
        o.put("reportWidenOnly", w.writeValueAsString(new MySQLDrift.Report(db, t, true, List.of(changes.get(1)), List.of(), List.of())));
        o.put("repairComplete", w.writeValueAsString(new MySQLDrift.DriftRepair(db, false, List.of("s1"), List.of(), List.of())));
        o.put("repairPartial", w.writeValueAsString(new MySQLDrift.DriftRepair(db, true, List.of(), List.of("w1"), List.of("f1"))));
        o.put("outcomeApplied", w.writeValueAsString(new MigrationOutcome(MigrationState.APPLIED, 2, 1, -1, null, 0, null)));
        o.put("outcomeResumed", w.writeValueAsString(new MigrationOutcome(MigrationState.APPLIED, 3, 0, 1, null, 0, null)));
        o.put("outcomeBlocked", w.writeValueAsString(new MigrationOutcome(MigrationState.NEEDS_ATTENTION, 0, 0, -1, "n fits INT", 3, null)));
        o.put("outcomeFailed", w.writeValueAsString(new MigrationOutcome(MigrationState.FAILED, 1, 0, -1, null, 0, "Duplicate column")));
        return o;
    }
}
