
const request = require("supertest");
const app = require("../app");

describe("Login Application", () => {

    test("Dashboard should reject unauthenticated users", async () => {
        const response = await request(app).get("/dashboard");

        expect(response.statusCode).toBe(401);
    });

});
