package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

final class DataTypeResolver {

    private static final Pattern ARRAY_SUFFIX = Pattern.compile("^(.+)\\[(\\d+)]\\s*$");

    private DataTypeResolver() {
    }

    static Result resolve(DataTypeManager dtm, String dataTypeName, Object arrayCountValue) {
        if (dataTypeName == null || dataTypeName.isBlank()) {
            return Result.error("Data type name is required");
        }

        String baseTypeName = dataTypeName.trim();
        Integer arrayCount = parseArrayCount(arrayCountValue);
        if (arrayCountValue != null && arrayCount == null) {
            return Result.error("array_count must be an integer");
        }

        Matcher matcher = ARRAY_SUFFIX.matcher(baseTypeName);
        if (matcher.matches()) {
            if (arrayCount != null) {
                return Result.error("Specify array size either with data_type suffix syntax or array_count, not both");
            }
            baseTypeName = matcher.group(1).trim();
            arrayCount = Integer.parseInt(matcher.group(2));
        }

        if (arrayCount != null && arrayCount < 1) {
            return Result.error("array_count must be >= 1");
        }

        DataType baseType = resolveBaseType(dtm, baseTypeName);
        if (baseType == null) {
            return Result.error("Data type not found: " + baseTypeName);
        }

        if (arrayCount == null) {
            return Result.ok(baseType);
        }

        int elementLength = baseType.getLength();
        if (elementLength <= 0) {
            return Result.error("Cannot build array of variable-length type '" + baseType.getName() + "'");
        }

        return Result.ok(new ArrayDataType(baseType, arrayCount, elementLength));
    }

    private static Integer parseArrayCount(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            double doubleValue = ((Number) value).doubleValue();
            int intValue = ((Number) value).intValue();
            return doubleValue == intValue ? intValue : null;
        }
        if (value instanceof String) {
            try {
                return Integer.parseInt(((String) value).trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static DataType resolveBaseType(DataTypeManager dtm, String dataTypeName) {
        DataType dataType = null;
        if (dataTypeName.startsWith("/")) {
            dataType = dtm.getDataType(dataTypeName);
        }
        if (dataType == null) {
            dataType = dtm.getDataType("/" + dataTypeName);
        }
        if (dataType == null) {
            dataType = dtm.getDataType(dataTypeName);
        }
        if (dataType != null) {
            return dataType;
        }

        List<DataType> allTypes = new ArrayList<>();
        dtm.getAllDataTypes(allTypes);
        for (DataType candidate : allTypes) {
            if (candidate.getName().equals(dataTypeName)) {
                return candidate;
            }
        }
        return null;
    }

    static final class Result {
        final DataType dataType;
        final String errorMessage;

        private Result(DataType dataType, String errorMessage) {
            this.dataType = dataType;
            this.errorMessage = errorMessage;
        }

        static Result ok(DataType dataType) {
            return new Result(dataType, null);
        }

        static Result error(String errorMessage) {
            return new Result(null, errorMessage);
        }

        boolean isError() {
            return errorMessage != null;
        }
    }
}
