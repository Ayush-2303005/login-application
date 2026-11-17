
const request = require("supertest");
const app = require("../app");

describe("Login Application", () => {

    test("Dashboard should reject unauthenticated users", async () => {
        const response = await request(app)
            .get("/dashboard");

        expect(response.statusCode).toBe(401);
        expect(response.body.message).toContain("Unauthorized");
    });

    test("Health check should return OK", async () => {
        const response = await request(app)
            .get("/health");

        expect(response.statusCode).toBe(200);
        expect(response.body.status).toBe("OK");
    });

    test("Login should reject missing credentials", async () => {
        const response = await request(app)
            .post("/login")
            .send({});

        expect(response.statusCode).toBe(400);
    });

    test("Registration should reject missing credentials", async () => {
        const response = await request(app)
            .post("/register")
            .send({});

        expect(response.statusCode).toBe(400);
    });

});
