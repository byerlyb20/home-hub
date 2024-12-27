import { Permissions } from "./permissions"

export type User = {
    id: number,
    username: string,
    permissions: Permissions
}