export async function GET() {
  const users = await db.user.findMany();
  return Response.json(users);
}

const db = {
  user: {
    async findMany() {
      return [{ id: "user_1", email: "admin@example.invalid" }];
    },
  },
};
