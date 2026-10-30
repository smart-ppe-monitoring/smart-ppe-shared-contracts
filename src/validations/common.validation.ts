import { z } from "zod";

/**
 * Standard reusable UUID validation schema
 */
export const uuidSchema = z
  .string({
    required_error: "ID is required",
    invalid_type_error: "ID must be a string",
  })
  .uuid("Invalid UUID format");

/**
 * Factory for creating reusable single-parameter UUID schemas
 * E.g. uuidParamSchema("id") -> z.object({ id: z.string().uuid(...) })
 */
export function createUuidParamSchema<K extends string = "id">(
  paramName: K = "id" as K,
  errorMessage: string = `Invalid ${paramName} format`,
) {
  return z.object({
    [paramName]: z
      .string({
        required_error: `${paramName} is required`,
        invalid_type_error: `${paramName} must be a string`,
      })
      .uuid(errorMessage),
  } as Record<K, z.ZodString>);
}

/**
 * Default standard param schema for :id
 */
export const standardIdParamSchema = createUuidParamSchema(
  "id",
  "Invalid ID format",
);

/**
 * Standard reusable pagination query schema
 * Giới hạn page tối đa 1,000,000 để chống tràn số nguyên PostgreSQL 22003 (SEC-10)
 */
export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(1000000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().optional(),
  sortBy: z.string().optional(),
  order: z.enum(["asc", "desc"]).default("desc"),
});

/**
 * Standard Route Key validation schema for system settings, feature flags, configuration keys
 * Chặn các từ khóa prototype pollution (__proto__, constructor, prototype) và path traversal (SEC-11)
 */
export const routeKeySchema = z
  .string({
    required_error: "Key is required",
    invalid_type_error: "Key must be a string",
  })
  .min(2, "Key must be at least 2 characters")
  .max(100, "Key must not exceed 100 characters")
  .regex(
    /^[a-z0-9_.-]+$/i,
    "Key must contain only letters, numbers, dots, hyphens, and underscores",
  )
  .refine(
    (val) => {
      const parts = val.split(".");
      return (
        !parts.some((part) =>
          ["__proto__", "constructor", "prototype", ""].includes(
            part.toLowerCase(),
          ),
        ) && !val.includes("..")
      );
    },
    {
      message:
        "Key cannot contain reserved prototype property names or directory traversal",
    },
  );

/**
 * Factory for creating reusable single-parameter Route Key schemas
 * E.g. createRouteKeyParamSchema("key") -> z.object({ key: routeKeySchema })
 */
export function createRouteKeyParamSchema<K extends string = "key">(
  paramName: K = "key" as K,
) {
  return z.object({
    [paramName]: routeKeySchema,
  } as Record<K, typeof routeKeySchema>);
}

/**
 * Default standard param schema for :key
 */
export const standardKeyParamSchema = createRouteKeyParamSchema("key");
